"""Static detector stub that produces hints.json and static_results.json.

This is an intentionally small, well-documented stub to drive integration and
tests. It reads preproc artifacts via `preproc_adapter`, obtains (or creates)
a Ghidra export via `ghidra_adapter`, and writes minimal, schema-shaped outputs
under `analysis/static/<file_hash>/`.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from .preproc_adapter import load_preproc, ensure_output_dir
from .ghidra_adapter import find_cached_export, run_ghidra_headless_stub, read_ghidra_functions


SCHEMA_VERSION = "1.0"


def timestamp_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: str, data: Dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def run_static_detector(preproc_dir: str, analysis_base: str = "analysis/static", ghidra_export_dir: str = "analysis/static/ghidra-export", force: bool = False) -> Dict[str, Any]:
    """Run the static detector stub for a preproc artifact.

    Produces:
      - analysis/static/<file_hash>/hints.json
      - analysis/static/<file_hash>/static_results.json

    Returns the static_results dictionary.
    """
    info = load_preproc(preproc_dir)
    file_hash = info["file_hash"]

    out_dir = Path(analysis_base) / file_hash
    out_dir.mkdir(parents=True, exist_ok=True)

    hints_path = out_dir / "hints.json"
    static_results_path = out_dir / "static_results.json"

    if hints_path.exists() and static_results_path.exists() and not force:
        # read and return cached
        with static_results_path.open("r", encoding="utf-8") as fh:
            return json.load(fh)

    # Get or create a ghidra export (stub)
    export_path = find_cached_export(ghidra_export_dir, file_hash)
    if not export_path:
        export_path = run_ghidra_headless_stub(info["input_path"], ghidra_export_dir, file_hash)

    ghidra_data = read_ghidra_functions(export_path)

    # Build a minimal hints.json using available ghidra_data
    hints = []
    for idx, fn in enumerate(ghidra_data.get("functions", [])):
        hints.append({
            "id": f"h-{idx+1}",
            "type": "function",
            "name": fn.get("name") or None,
            "address_or_range": fn.get("range") or fn.get("entry") or {},
            "confidence": 0.2,
            "reason_tags": [],
        })

    hints_doc = {
        "file_hash": file_hash,
        "schema_version": SCHEMA_VERSION,
        "language": info["metadata"].get("language"),
        "timestamp": timestamp_now(),
        "hints": hints,
    }

    write_json(str(hints_path), hints_doc)

    # static_results: minimal placeholder
    static_results = {
        "file_hash": file_hash,
        "schema_version": SCHEMA_VERSION,
        "timestamp": timestamp_now(),
        "findings": [],
        "hints_path": str(hints_path),
    }

    write_json(str(static_results_path), static_results)

    return static_results


if __name__ == "__main__":
    # Quick local CLI driver for manual testing
    import sys

    if len(sys.argv) < 2:
        print("Usage: python -m src.detection.static_detector <preproc_dir> [--force]")
        raise SystemExit(2)

    preproc_dir = sys.argv[1]
    force = "--force" in sys.argv[2:]
    res = run_static_detector(preproc_dir, force=force)
    print("Wrote static results for", res.get("file_hash"))
