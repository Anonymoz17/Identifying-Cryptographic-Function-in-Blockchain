"""Small helper to run the preprocessing scaffold from the command line.

Usage:
    python tools\run_preproc.py --workdir ./case_demo
    python tools\run_preproc.py --manifest ./case_demo/inputs.manifest.json --workdir ./case_demo

The script will read inputs.manifest.json (if provided) and call
`auditor.preproc.preprocess_items` with a progress callback that prints counts.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
from pathlib import Path

sys.path.insert(0, Path(".").resolve().as_posix())


def load_manifest(path):
    p = Path(path)
    with p.open("r", encoding="utf-8") as f:
        return json.load(f).get("items", [])


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("--workdir", default="./case_demo")
    p.add_argument("--manifest", default=None)
    args = p.parse_args(argv)

    wd = Path(args.workdir).resolve()
    wd.mkdir(parents=True, exist_ok=True)

    if args.manifest:
        manifest_path = Path(args.manifest).resolve()
    else:
        manifest_path = wd / "inputs.manifest.json"

    if not manifest_path.exists():
        print(
            f"Manifest not found at {manifest_path}. Run intake first (UI or auditor.cli)."
        )
        return 2

    items = load_manifest(manifest_path)
    total = len(items)
    print(f"Loaded manifest with {total} items from {manifest_path}")

    cancel_event = threading.Event()

    # Import the preproc function here to avoid module-level side-effects (E402)
    from auditor.preproc import preprocess_items

    def progress_cb(processed, total):
        print(f"Preproc: {processed}/{total}", end="\r", flush=True)

    try:
        res = preprocess_items(
            items, str(wd), progress_cb=progress_cb, cancel_event=cancel_event
        )
        stats = res.get("stats", {})
        print("\nPreprocessing finished, index lines:", stats.get("index_lines"))
        print("Manifest:", res.get("manifest_path"))
        print("Check", str((wd / "preproc")))
        return 0
    except KeyboardInterrupt:
        cancel_event.set()
        print("\nPreprocessing cancelled by user")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
