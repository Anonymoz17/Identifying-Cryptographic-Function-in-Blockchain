"""Summarize detector results (NDJSON) into CSV or JSON reports.

Usage:
    python tools/summarize_detections.py detector_results.ndjson --out report.csv --top 20

Options:
    --out <path>    Path to write CSV or JSON. Extension determines format (.csv/.json). If omitted prints to stdout.
    --top N         Only include top N rules by count.
    --include-engines  Include per-engine breakdown in JSON output.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict


def parse_ndjson(path: Path):
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            yield json.loads(line)
        except Exception:
            continue


def summarize(path: Path):
    stats: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "conf_sum": 0.0, "engines": defaultdict(int)}
    )
    for obj in parse_ndjson(path):
        rule = obj.get("rule") or "<unknown>"
        conf = float(obj.get("confidence", 0.0))
        eng = obj.get("engine") or "unknown"
        s = stats[rule]
        s["count"] += 1
        s["conf_sum"] += conf
        s["engines"][eng] += 1
    # compute derived values
    rows = []
    for rule, v in stats.items():
        avg = v["conf_sum"] / v["count"] if v["count"] else 0.0
        rows.append(
            {
                "rule": rule,
                "count": v["count"],
                "avg_confidence": round(avg, 4),
                "engines": dict(v["engines"]),
            }
        )
    rows.sort(key=lambda r: (-r["count"], -r["avg_confidence"], r["rule"]))
    return rows


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("ndjson")
    p.add_argument("--out", help="output file (csv or json)")
    p.add_argument("--top", type=int, default=0, help="top N rules to include")
    p.add_argument(
        "--include-engines",
        action="store_true",
        help="include per-engine breakdown in JSON output",
    )
    args = p.parse_args(argv)

    path = Path(args.ndjson)
    if not path.exists():
        print(f"File not found: {path}")
        return 1

    rows = summarize(path)
    if args.top and args.top > 0:
        rows = rows[: args.top]

    if args.out:
        outp = Path(args.out)
        if outp.suffix.lower() == ".csv":
            with outp.open("w", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["rule", "count", "avg_confidence", "engines"])
                for r in rows:
                    engines = ";".join(
                        [f"{k}:{v}" for k, v in r.get("engines", {}).items()]
                    )
                    writer.writerow(
                        [r["rule"], r["count"], r["avg_confidence"], engines]
                    )
        else:
            # json
            out_rows = []
            for r in rows:
                rec = {
                    "rule": r["rule"],
                    "count": r["count"],
                    "avg_confidence": r["avg_confidence"],
                }
                if args.include_engines:
                    rec["engines"] = r.get("engines", {})
                out_rows.append(rec)
            outp.write_text(json.dumps(out_rows, indent=2), encoding="utf-8")
        print(f"Wrote report to {outp}")
    else:
        print("rule\tcount\tavg_confidence\tengines")
        for r in rows:
            engines = ",".join([f"{k}:{v}" for k, v in r.get("engines", {}).items()])
            print(f"{r['rule']}\t{r['count']}\t{r['avg_confidence']}\t{engines}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
