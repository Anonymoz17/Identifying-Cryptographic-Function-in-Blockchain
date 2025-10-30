"""Quick consumer to run the GhidraAdapter locally against a case workspace.

This is useful to validate the adapter without running the full detector pipeline.
"""

from __future__ import annotations

import json
from pathlib import Path

from src.detectors.ghidra_adapter import GhidraAdapter
from src.detectors.runner import load_manifest_paths


def main(case_dir: str = "tools/case_demo/CASE-001"):
    case = Path(case_dir)
    manifest = case / "inputs.manifest.ndjson"
    if not manifest.exists():
        print("Manifest not found:", manifest)
        return
    files = load_manifest_paths(str(manifest), base_dir=str(case))
    g = GhidraAdapter(exports_root=str(case / "artifacts" / "ghidra_exports"))
    found = 0
    for d in g.scan_files(files):
        print(
            json.dumps(
                {
                    "path": d.path,
                    "rule": d.rule,
                    "details": d.details,
                    "engine": d.engine,
                }
            )
        )
        found += 1
    print(f"GhidraAdapter produced {found} detections")


if __name__ == "__main__":
    main()
