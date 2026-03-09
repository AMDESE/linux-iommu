#!/usr/bin/env python3
# funclat.py - measure entry-exit latency of a kernel function using eBPF (BCC)
#
# Outputs: min / avg / max / p50 / p99 / p99.9 (microseconds)
#
# Examples:
#   sudo ./funclat.py do_sys_open
#   sudo ./funclat.py --pid 1234 do_sys_open
#   sudo ./funclat.py --interval 5 do_sys_open
#
# Notes:
# - Target must be a probeable kernel symbol (not fully inlined).
# - Percentiles come from a log2 histogram; results are approximate within bucket ranges.
#
# Dependencies:
#   - BCC Python bindings (e.g., ubuntu: python3-bpfcc / bpfcc-tools)
#
# Tip (debug verifier / attach issues):
#   - Add --debug to print BPF verifier logs (can be very verbose).
#   - Check symbol exists:
#       sudo cat /proc/kallsyms | grep -w <func>
#       sudo cat /sys/kernel/debug/tracing/available_filter_functions | grep -w <func>

import argparse
import signal
import time
from bcc import BPF


BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>

struct stat_t {
    u64 count;
    u64 total_us;
    u64 min_us;
    u64 max_us;
};

BPF_HASH(start, u64, u64);              // tid -> start ns
BPF_PERCPU_ARRAY(stats, struct stat_t, 1);
BPF_HISTOGRAM(lat_hist);                // log2 histogram of latency (us)

static __always_inline u64 get_tid(void) {
    return (u64)(bpf_get_current_pid_tgid() & 0xffffffffULL);
}

int trace_entry(struct pt_regs *ctx) {
    FILTER_PID

    u64 tid = get_tid();
    u64 ts = bpf_ktime_get_ns();
    start.update(&tid, &ts);
    return 0;
}

int trace_return(struct pt_regs *ctx) {
    FILTER_PID

    u64 tid = get_tid();
    u64 *tsp = start.lookup(&tid);
    if (!tsp)
        return 0;

    u64 delta_ns = bpf_ktime_get_ns() - *tsp;
    start.delete(&tid);

    u64 delta_us = delta_ns / 1000;
    if (delta_us == 0)
        delta_us = 1;

    lat_hist.increment(bpf_log2l(delta_us));

    u32 idx = 0;
    struct stat_t *s = stats.lookup(&idx);
    if (!s)
        return 0;

    s->count++;
    s->total_us += delta_us;

    if (s->min_us == 0 || delta_us < s->min_us)
        s->min_us = delta_us;

    if (delta_us > s->max_us)
        s->max_us = delta_us;

    return 0;
}
"""


def build_bpf(pid, func, debug=False):
    if pid is None:
        filt = ""
    else:
        # Filter on TGID (upper 32 bits)
        filt = f"""
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 tgid = pid_tgid >> 32;
        if (tgid != {pid}) return 0;
        """

    text = BPF_PROGRAM.replace("FILTER_PID", filt)
    b = BPF(text=text, debug=4 if debug else 0)

    # Attach probes
    b.attach_kprobe(event=func, fn_name="trace_entry")
    b.attach_kretprobe(event=func, fn_name="trace_return")
    return b


def read_stats(b):
    stats = b.get_table("stats")
    idx = 0

    # per-CPU array of struct stat_t
    per_cpu_vals = stats[idx]

    total_count = 0
    total_us = 0
    min_us = 0
    max_us = 0

    for v in per_cpu_vals:
        c = int(v.count)
        t = int(v.total_us)
        mn = int(v.min_us)
        mx = int(v.max_us)

        total_count += c
        total_us += t

        if mn != 0 and (min_us == 0 or mn < min_us):
            min_us = mn
        if mx > max_us:
            max_us = mx

    avg_us = (total_us / total_count) if total_count else 0.0
    return total_count, min_us, avg_us, max_us


def hist_to_percentiles(b, percentiles=(0.50, 0.99, 0.999)):
    """
    lat_hist is log2 bucketed by bpf_log2l(lat_us).
    Bucket k approximates latency in [2^k, 2^(k+1)-1] us.
    We compute percentiles by cumulative counts and return the bucket range.
    """
    hist = b.get_table("lat_hist")
    items = sorted(hist.items(), key=lambda kv: kv[0].value)

    total = sum(int(v.value) for _, v in items)
    if total == 0:
        return {p: None for p in percentiles}, 0

    # ceil() without float edge cases
    targets = []
    for p in percentiles:
        # smallest integer >= total*p
        # (total*p) might not be integer; do integer math via + (den-1)/den not easy with float
        # use float but protect by adding tiny epsilon then int()
        targets.append(int(total * p + 0.999999))

    out = {}
    cum = 0
    ti = 0

    for k_key, v in items:
        k = int(k_key.value)
        cnt = int(v.value)
        if cnt == 0:
            continue
        cum += cnt
        while ti < len(targets) and cum >= targets[ti]:
            p = percentiles[ti]
            low = 1 << k
            high = (1 << (k + 1)) - 1 if k < 63 else (1 << 63)
            out[p] = (low, high)
            ti += 1
        if ti >= len(targets):
            break

    for p in percentiles:
        out.setdefault(p, None)

    return out, total


def clear_maps(b):
    b["lat_hist"].clear()
    b["stats"].clear()


def fmt_bucket_range(rng):
    if rng is None:
        return "n/a"
    low, high = rng
    if low == high:
        return f"{low} us"
    return f"{low}-{high} us"


def main():
    ap = argparse.ArgumentParser(
        description="Measure entry-exit latency of a kernel function using eBPF (BCC kprobe/kretprobe)."
    )
    ap.add_argument("func", help="Kernel function symbol name (e.g., do_sys_open)")
    ap.add_argument("--pid", type=int, default=None, help="Filter by process TGID (userspace PID)")
    ap.add_argument("--interval", type=int, default=0,
                    help="Print every N seconds (0 = run until Ctrl-C then print once)")
    ap.add_argument("--debug", action="store_true",
                    help="Enable BPF verifier debug output (very verbose)")
    args = ap.parse_args()

    b = build_bpf(args.pid, args.func, debug=args.debug)

    exiting = False

    def on_sigint(sig, frame):
        nonlocal exiting
        exiting = True

    signal.signal(signal.SIGINT, on_sigint)

    def print_report():
        count, mn, avg, mx = read_stats(b)
        pct, _total = hist_to_percentiles(b, (0.50, 0.99, 0.999))

        hdr = f"Function: {args.func}"
        if args.pid:
            hdr += f"  (pid={args.pid})"
        print("\n" + hdr)
        print(f"Samples:  {count}")
        if count == 0:
            return
        print(f"Min:      {mn} us")
        print(f"Avg:      {avg:.2f} us")
        print(f"Max:      {mx} us")
        print(f"P50:      {fmt_bucket_range(pct[0.50])}")
        print(f"P99:      {fmt_bucket_range(pct[0.99])}")
        print(f"P99.9:    {fmt_bucket_range(pct[0.999])}")

    if args.interval and args.interval > 0:
        while not exiting:
            time.sleep(args.interval)
            print_report()
            clear_maps(b)
    else:
        while not exiting:
            time.sleep(0.2)
        print_report()


if __name__ == "__main__":
    main()
