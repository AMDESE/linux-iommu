#!/usr/bin/env python3
import sys, math, time
from bisect import insort

# Simple exact percentiles by keeping a sorted list.
# If you expect millions of samples, switch to a streaming sketch (t-digest).
samples = []          # sorted
count = 0
total = 0
min_v = None
max_v = None
last_report = time.time()

def percentile(sorted_list, p: float) -> float:
    """Exact percentile with linear interpolation (p in [0,100])."""
    if not sorted_list:
        return float("nan")
    n = len(sorted_list)
    if n == 1:
        return float(sorted_list[0])
    r = (p / 100.0) * (n - 1)
    lo = int(math.floor(r))
    hi = int(math.ceil(r))
    if lo == hi:
        return float(sorted_list[lo])
    frac = r - lo
    return sorted_list[lo] * (1.0 - frac) + sorted_list[hi] * frac

def report():
    global count, total, min_v, max_v
    if count == 0:
        return
    avg = total / count
    p50 = percentile(samples, 50.0)
    p99 = percentile(samples, 99.0)
    p999 = percentile(samples, 99.9)
    print(
        f"samples={count} "
        f"min={min_v} avg={avg:.3f} max={max_v} "
        f"p50={p50:.3f} p99={p99:.3f} p99.9={p999:.3f}",
        flush=True,
    )

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    if line.startswith("Tracing"):
        continue

    try:
        v = int(line)
    except ValueError:
        continue

    # Update running stats
    count += 1
    total += v
    min_v = v if min_v is None else min(min_v, v)
    max_v = v if max_v is None else max(max_v, v)

    # Keep exact percentile data in sorted order
    insort(samples, v)

    # Periodic report (every ~2 seconds)
    now = time.time()
    if now - last_report >= 2.0:
        report()
        last_report = now

# Final report
report()
