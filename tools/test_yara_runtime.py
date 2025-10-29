from __future__ import annotations

import json
from pathlib import Path

from src.detectors.adapter import YaraAdapter
from src.detectors.runner import load_manifest_paths


def main():
    case_dir = Path("tools/case_demo/CASE-001")
    manifest = case_dir / "inputs.manifest.ndjson"
    if not manifest.exists():
        print("Manifest not found:", manifest)
        return

    files = load_manifest_paths(str(manifest), base_dir=str(case_dir))
    print(f"Loaded {len(files)} files from manifest; example: {files[:3]}")

    rules_path = Path("src/detectors/yara/crypto.yar")
    print("Using rules:", rules_path)

    try:
        ada = YaraAdapter(rules_path=str(rules_path))
    except Exception as e:
        print("YaraAdapter init failed:", e)
        return

    found = False
    for d in ada.scan_files(files):
        print(
            json.dumps(
                {
                    "path": d.path,
                    "offset": d.offset,
                    "rule": d.rule,
                    "details": d.details,
                    "engine": d.engine,
                }
            )
        )
        found = True

    if not found:
        print(
            "No yara detections produced (adapter may have fallen back to regex or rules did not match)"
        )


if __name__ == "__main__":
    main()
