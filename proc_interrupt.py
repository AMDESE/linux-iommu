#!/usr/bin/env python3
import argparse
import re
import sys
from typing import List, Tuple, Dict, Any

CPU_HDR_RE = re.compile(r"\bCPU(\d+)\b")


def parse_proc_interrupts(text: str) -> Tuple[List[int], List[Dict[str, Any]]]:
    """
    Parse /proc/interrupts

    Returns:
        cpu_ids: [0,1,2,...]
        rows: [
          {
            "row_name": "0:" / "NMI:" ...
            "counts": [int per cpu]
            "desc": "IO-APIC 2-edge timer"
          }
        ]
    """
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

        counts = []
        desc_tokens = []

        for tok in parts[1:]:
            if len(counts) < ncpus and tok.isdigit():
                counts.append(int(tok))
            else:
                desc_tokens.append(tok)

        if len(counts) < ncpus:
            counts.extend([0] * (ncpus - len(counts)))

        desc = " ".join(desc_tokens)

        rows.append({
            "row_name": row_name,
            "counts": counts[:ncpus],
            "desc": desc,
        })

    return cpu_ids, rows


def summarize(cpu_ids: List[int], rows: List[Dict[str, Any]], top_cpus: int = 0):
    name_w = max(len(r["row_name"]) for r in rows) + 2
    desc_w = max(len(r["desc"]) for r in rows) + 2

    for r in rows:
        counts = r["counts"]
        total = sum(counts)

        cpu_list = [(cpu_ids[i], c) for i, c in enumerate(counts) if c > 0]

        if top_cpus > 0:
            cpu_list.sort(key=lambda x: x[1], reverse=True)
            cpu_list = cpu_list[:top_cpus]

        if cpu_list:
            cpu_str = ", ".join([f"{cid}={c}" for cid, c in cpu_list])
        else:
            cpu_str = "-"

        print(f"{r['row_name']:<{name_w}}{r['desc']:<{desc_w}}total={total:<12} cpus: {cpu_str}")


def main():
    parser = argparse.ArgumentParser(description="IRQ row summary from /proc/interrupts")
    parser.add_argument("-f", "--file", default="/proc/interrupts",
                        help="Input file (default: /proc/interrupts, or '-' for stdin)")
    parser.add_argument("--top-cpus", type=int, default=0,
                        help="Show only top N CPUs per row")
    args = parser.parse_args()

    if args.file == "-":
        text = sys.stdin.read()
    else:
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()

    cpu_ids, rows = parse_proc_interrupts(text)
    summarize(cpu_ids, rows, args.top_cpus)


if __name__ == "__main__":
    main()

