#!/usr/bin/env python3
import argparse
import re
import sys
import time
from typing import List, Tuple, Dict, Any, Optional

CPU_HDR_RE = re.compile(r"\bCPU(\d+)\b")


def parse_proc_interrupts(text: str) -> Tuple[List[int], List[Dict[str, Any]]]:
    lines = [ln.rstrip("\n") for ln in text.splitlines() if ln.strip()]
    if not lines:
        raise ValueError("Empty input")

    header_idx = None
    for i, ln in enumerate(lines):
        if "CPU" in ln and CPU_HDR_RE.search(ln):
            header_idx = i
            break
    if header_idx is None:
        raise ValueError("CPU header not found")

    header = lines[header_idx]
    cpu_ids = [int(m.group(1)) for m in CPU_HDR_RE.finditer(header)]
    ncpus = len(cpu_ids)

    rows: List[Dict[str, Any]] = []
    for ln in lines[header_idx + 1:]:
        parts = ln.split()
        if not parts:
            continue

        row_name = parts[0]
        counts: List[int] = []
        desc_tokens: List[str] = []

        for tok in parts[1:]:
            if len(counts) < ncpus and tok.isdigit():
                counts.append(int(tok))
            else:
                desc_tokens.append(tok)

        if len(counts) < ncpus:
            counts.extend([0] * (ncpus - len(counts)))

        rows.append({
            "row_name": row_name,
            "counts": counts[:ncpus],
            "desc": " ".join(desc_tokens),
        })

    return cpu_ids, rows


def rows_to_map(rows: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {r["row_name"]: r for r in rows}


def clear_screen():
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()


def read_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def compute_total_rates(prev_rows: Dict[str, Dict[str, Any]],
                        cur_rows: Dict[str, Dict[str, Any]],
                        dt: float) -> Dict[str, float]:
    rates: Dict[str, float] = {}
    if dt <= 0:
        return rates
    for row_name, cur in cur_rows.items():
        cur_total = sum(cur["counts"])
        prev = prev_rows.get(row_name)
        prev_total = sum(prev["counts"]) if prev else cur_total
        delta = cur_total - prev_total
        if delta < 0:
            delta = 0
        rates[row_name] = delta / dt
    return rates


def compute_percpu_rates(prev_rows: Dict[str, Dict[str, Any]],
                         cur_rows: Dict[str, Dict[str, Any]],
                         cpu_ids: List[int],
                         dt: float) -> Dict[str, Dict[int, float]]:
    """
    Returns: rates[row_name][cpu_id] = intr/s
    """
    out: Dict[str, Dict[int, float]] = {}
    if dt <= 0:
        return out

    for row_name, cur in cur_rows.items():
        prev = prev_rows.get(row_name)
        cur_counts = cur["counts"]
        prev_counts = prev["counts"] if prev else cur_counts

        row_rates: Dict[int, float] = {}
        for i, cpu_id in enumerate(cpu_ids):
            d = cur_counts[i] - prev_counts[i]
            if d < 0:
                d = 0
            r = d / dt
            if r != 0.0:
                row_rates[cpu_id] = r
        out[row_name] = row_rates

    return out


def format_output_counts(cpu_ids: List[int],
                         rows: List[Dict[str, Any]],
                         top_cpus: int = 0,
                         hide_zero: bool = False) -> str:
    if not rows:
        return ""

    name_w = max(len(r["row_name"]) for r in rows) + 2
    desc_w = max(len(r["desc"]) for r in rows) + 2

    lines = []
    hdr = f"{'NAME':<{name_w}}{'DESCRIPTION':<{desc_w}}{'TOTAL':>14}  CPUS"
    lines.append(hdr)
    lines.append("-" * len(hdr))

    for r in rows:
        total = sum(r["counts"])
        if hide_zero and total == 0:
            continue

        cpu_list = [(cpu_ids[i], c) for i, c in enumerate(r["counts"]) if c > 0]
        if top_cpus > 0:
            cpu_list.sort(key=lambda x: x[1], reverse=True)
            cpu_list = cpu_list[:top_cpus]

        cpu_str = ", ".join([f"CPU{cid}={c}" for cid, c in cpu_list]) if cpu_list else "-"
        lines.append(f"{r['row_name']:<{name_w}}{r['desc']:<{desc_w}}{total:>14d}  {cpu_str}")

    return "\n".join(lines)


def format_output_rates(cpu_ids: List[int],
                        rows: List[Dict[str, Any]],
                        total_rates: Dict[str, float],
                        percpu_rates: Dict[str, Dict[int, float]],
                        top_cpus: int = 0,
                        hide_zero: bool = False) -> str:
    """
    NAME | DESCRIPTION | TOTAL | TOTAL/s | CPUS/s (only non-zero CPU rates)
    """
    if not rows:
        return ""

    name_w = max(len(r["row_name"]) for r in rows) + 2
    desc_w = max(len(r["desc"]) for r in rows) + 2

    lines = []
    hdr = (
        f"{'NAME':<{name_w}}"
        f"{'DESCRIPTION':<{desc_w}}"
        f"{'TOTAL':>14}  "
        f"{'TOTAL/s':>12}  "
        f"CPUS/s"
    )
    lines.append(hdr)
    lines.append("-" * len(hdr))

    for r in rows:
        row_name = r["row_name"]
        total = sum(r["counts"])
        rate_total = total_rates.get(row_name, 0.0)

        if hide_zero and total == 0:
            continue

        row_cpu_rates = percpu_rates.get(row_name, {})  # cpu_id -> rate
        cpu_items = list(row_cpu_rates.items())  # (cpu_id, rate)
        # sort by rate desc
        cpu_items.sort(key=lambda x: x[1], reverse=True)
        if top_cpus > 0:
            cpu_items = cpu_items[:top_cpus]

        cpu_str = ", ".join([f"CPU{cid}={rt:.2f}/s" for cid, rt in cpu_items]) if cpu_items else "-"

        lines.append(
            f"{row_name:<{name_w}}"
            f"{r['desc']:<{desc_w}}"
            f"{total:>14d}  "
            f"{rate_total:>12.2f}  "
            f"{cpu_str}"
        )

    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Summarize /proc/interrupts: totals, CPUs, optional watch or one-shot rate.")
    ap.add_argument("-f", "--file", default="/proc/interrupts",
                    help="Input file (default: /proc/interrupts). Use '-' for stdin.")
    ap.add_argument("--top-cpus", type=int, default=0,
                    help="Limit CPUs shown (by highest count or highest rate). Default: show all nonzero.")
    ap.add_argument("-z", "--hide-zero", action="store_true",
                    help="Hide rows where TOTAL (at end of capture) is zero.")

    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("-w", "--watch", action="store_true",
                      help="Continuously refresh output and show per-row IRQ rate.")
    mode.add_argument("-r", "--rate-interval", type=float, default=None, metavar="SECONDS",
                      help="Collect for SECONDS, then print one-shot intr/s per row and per CPU (only nonzero CPUs).")

    ap.add_argument("-i", "--interval", type=float, default=1.0,
                    help="Refresh interval seconds for --watch (default: 1.0).")

    args = ap.parse_args()

    if (args.watch or args.rate_interval is not None) and args.file == "-":
        print("Error: -w/-r requires a readable file path (e.g., /proc/interrupts), not stdin '-'.", file=sys.stderr)
        sys.exit(2)

    # One-shot totals (no rates)
    if not args.watch and args.rate_interval is None:
        text = read_text(args.file)
        cpu_ids, rows = parse_proc_interrupts(text)
        print(format_output_counts(cpu_ids, rows, args.top_cpus, args.hide_zero))
        return

    # One-shot rate mode (-r)
    if args.rate_interval is not None:
        if args.rate_interval <= 0:
            print("Error: -r/--rate-interval must be > 0", file=sys.stderr)
            sys.exit(2)

        t0 = time.time()
        cpu0, rows0 = parse_proc_interrupts(read_text(args.file))
        prev_map = rows_to_map(rows0)

        time.sleep(args.rate_interval)

        t1 = time.time()
        dt = t1 - t0

        cpu1, rows1 = parse_proc_interrupts(read_text(args.file))
        if cpu1 != cpu0:
            print("CPU layout changed during capture; cannot compute stable per-CPU rates.", file=sys.stderr)
            sys.exit(2)

        cur_map = rows_to_map(rows1)
        total_rates = compute_total_rates(prev_map, cur_map, dt)
        percpu_rates = compute_percpu_rates(prev_map, cur_map, cpu1, dt)

        print(f"Source: {args.file} | capture={dt:.3f}s | end={time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(format_output_rates(cpu1, rows1, total_rates, percpu_rates, args.top_cpus, args.hide_zero))
        return

    # Watch mode (-w)
    text0 = read_text(args.file)
    prev_cpu_ids, prev_rows = parse_proc_interrupts(text0)
    prev_map = rows_to_map(prev_rows)
    t0 = time.time()

    while True:
        time.sleep(max(0.01, args.interval))
        t1 = time.time()
        dt = t1 - t0
        t0 = t1

        cpu_ids, rows = parse_proc_interrupts(read_text(args.file))
        cur_map = rows_to_map(rows)

        if cpu_ids != prev_cpu_ids:
            prev_cpu_ids = cpu_ids
            prev_map = cur_map
            clear_screen()
            print("CPU layout changed; resetting rate baseline.\n")
            print(format_output_counts(cpu_ids, rows, args.top_cpus, args.hide_zero))
            continue

        total_rates = compute_total_rates(prev_map, cur_map, dt)
        percpu_rates = compute_percpu_rates(prev_map, cur_map, cpu_ids, dt)
        prev_map = cur_map

        clear_screen()
        print(f"Source: {args.file} | interval={args.interval:.2f}s | updated={time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(format_output_rates(cpu_ids, rows, total_rates, percpu_rates, args.top_cpus, args.hide_zero))


if __name__ == "__main__":
    main()
