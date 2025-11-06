"""Merger utilities to combine static + dynamic results into a final report.

This is a minimal implementation that supports static-only merging for the
free tier. When dynamic results are available they can be incorporated.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional


def timestamp_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def write_json(path: str, doc: Dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)


def merge_static_only(static_results_path: str, out_path: str, weights: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
    """Create a final_report.json from static_results only.

    Args:
        static_results_path: path to analysis/static/<file_hash>/static_results.json
        out_path: path to write final_report.json
        weights: optional weights dict (static/dynamic)

    Returns:
        final_report dict
    """
    with Path(static_results_path).open("r", encoding="utf-8") as fh:
        static = json.load(fh)

    file_hash = static.get("file_hash")
    schema_version = static.get("schema_version", "1.0")

    if weights is None:
        weights = {"static": 1.0, "dynamic": 0.0}

    merged_findings = []
    for f in static.get("findings", []):
        merged_findings.append({
            "id": f.get("id"),
            "symbols": [f.get("symbol")],
            "static_confidence": f.get("confidence", 0.0),
            "dynamic_confidence": None,
            "merged_confidence": f.get("confidence", 0.0),
            "verdict": "possible" if f.get("confidence", 0.0) >= 0.6 else "unlikely",
        })

    final = {
        "file_hash": file_hash,
        "schema_version": schema_version,
        "timestamp": timestamp_now(),
        "merged_findings": merged_findings,
        "weights": weights,
        "notes": "Static-only merge (free tier).",
    }

    write_json(out_path, final)
    return final
