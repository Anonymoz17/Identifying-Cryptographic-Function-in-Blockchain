"""Copy mock Ghidra export(s) into a case workspace so adapters can be tested

Usage:
    python tools/consume_ghidra_mock.py --case <case_dir>

This will scan the case's `preproc/` subfolders, and for each preproc sha it will
create `artifacts/ghidra_exports/<sha>/` and copy the mock `example_functions.json`
there. This allows testing the Ghidra adapter without running Ghidra.
"""

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MOCK_PATH = ROOT / "tools" / "ghidra" / "mock_exports" / "example_functions.json"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--case", required=True, help="Path to case directory")
    args = p.parse_args()
    case = Path(args.case).resolve()
    if not case.exists():
        raise SystemExit(f"case path not found: {case}")
    preproc_dir = case / "preproc"
    if not preproc_dir.exists():
        raise SystemExit(f"no preproc dir found under case: {preproc_dir}")
    for sha_dir in preproc_dir.iterdir():
        if not sha_dir.is_dir():
            continue
        sha = sha_dir.name
        dest_dir = case / "artifacts" / "ghidra_exports" / sha
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_file = dest_dir / f"{sha}_functions.json"
        shutil.copy(MOCK_PATH, dest_file)
        print(f"Copied mock export to {dest_file}")


if __name__ == "__main__":
    main()
