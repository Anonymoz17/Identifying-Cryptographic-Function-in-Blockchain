"""Package static results and write `static_results.json` (skeleton).

Adds provenance and links to any cached artifacts.
"""
from typing import Dict, Any
import json
import os


def package_results(file_hash: str, findings: Any, out_dir: str, meta: Dict = None) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "static_results.json")
    payload = {
        "file_hash": file_hash,
        "schema_version": "0.0.1",
        "findings": findings,
        "meta": meta or {},
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    return path
