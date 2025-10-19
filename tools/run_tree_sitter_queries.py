#!/usr/bin/env python3
"""Run Tree-sitter `.scm` queries against sample source files.

This is a lightweight CLI that uses the project's `TreeSitterDetector` to run
queries from `detectors/queries/*.scm` against files in a samples directory
or a single file. It's intended for local validation and for use in CI jobs
where a real `tree_sitter` runtime and compiled language library are available.

Usage examples:
    python tools/run_tree_sitter_queries.py --queries src/detectors/queries --samples samples/
    python tools/run_tree_sitter_queries.py --queries src/detectors/queries --file contracts/My.sol --lib-path /work/tree_sitter_langs.so

Notes:
- The script will exit with code 2 if `tree_sitter` is not importable. In CI,
  ensure the binding is installed and `TREE_SITTER_LANGS` env var or `--lib-path`
  points to a combined language library (e.g., built with tree-sitter CLI).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Iterable


def parse_args():
    p = argparse.ArgumentParser(
        description="Run tree-sitter .scm queries against sample files"
    )
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--samples", help="Directory containing sample files to scan")
    group.add_argument("--file", help="Single file to scan")
    p.add_argument(
        "--queries", required=True, help="Directory containing .scm query files"
    )
    p.add_argument(
        "--lib-path", help="Path to combined tree-sitter language library (optional)"
    )
    p.add_argument(
        "--json", action="store_true", help="Output detections as JSON lines"
    )
    p.add_argument(
        "--ext",
        action="append",
        help="File extensions to include when scanning samples (e.g. .sol). If omitted, common extensions will be used.",
    )
    return p.parse_args()


def iter_files(samples_dir: Path, exts: Iterable[str]):
    for p in samples_dir.rglob("*"):
        if p.is_file() and p.suffix in exts:
            yield str(p)


def main():
    args = parse_args()

    # lazy import to provide helpful error messages
    try:
        from src.detectors.tree_sitter_detector import TreeSitterDetector
    except Exception as e:
        print(
            "tree_sitter runtime not available or project not installed:",
            e,
            file=sys.stderr,
        )
        print(
            "Install 'tree_sitter' and ensure language libs are available (TREE_SITTER_LANGS or --lib-path).",
            file=sys.stderr,
        )
        return 2

    if args.lib_path:
        os.environ["TREE_SITTER_LANGS"] = args.lib_path

    queries_dir = args.queries
    detector = TreeSitterDetector(queries_dir=str(queries_dir))

    exts = args.ext or [".sol", ".go", ".js", ".py"]

    files = []
    if args.file:
        files = [args.file]
    else:
        files = list(iter_files(Path(args.samples), exts))

    if not files:
        print("No files to scan.")
        return 0

    for d in detector.scan_files(files):
        # convert detection to JSON-friendly dict
        dd = {
            "path": d.path,
            "offset": d.offset,
            "rule": d.rule,
            "engine": d.engine,
            "details": d.details,
        }
        if args.json:
            print(json.dumps(dd, ensure_ascii=False))
        else:
            # human readable
            line = d.details.get("line")
            col = d.details.get("col")
            capture = d.details.get("capture")
            snippet = d.details.get("snippet")
            addr = d.details.get("is_address")
            print(
                f"{d.path}:{line}:{col} {d.rule} [{capture}] address={addr} -- {snippet}"
            )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
