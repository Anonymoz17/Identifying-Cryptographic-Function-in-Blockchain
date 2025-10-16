"""Package an arbitrary directory using auditor.evidence.build_evidence_pack

Usage:
    python tools/run_pack_on_dir.py --dir PATH --count N

This script will generate N files in the directory (if N>0) using generate_scope
and then call build_evidence_pack with a progress callback that prints sparse updates.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path


def progress_cb(i, total):
    if total and total > 0:
        # print sparse updates
        if i % max(1, total // 20) == 0 or i == 1 or i == total:
            print(f"pack progress: {i}/{total}")
    else:
        if i % 200 == 0:
            print(f"pack progress: {i}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default="tools/large_scope", help="Directory to package")
    ap.add_argument(
        "--count",
        type=int,
        default=0,
        help="If >0, generate this many files using generate_scope.py first",
    )
    ns = ap.parse_args()

    scope = Path(ns.dir).resolve()
    if ns.count and ns.count > 0:
        print(f"Generating {ns.count} files under {scope} (may take a while)")
        import subprocess

        subprocess.check_call(
            [
                sys.executable,
                "tools/generate_scope.py",
                "--dir",
                str(scope),
                "--count",
                str(ns.count),
                "--min-size",
                "512",
                "--max-size",
                "4096",
            ]
        )

    # collect all files under scope and run packer
    files = [p for p in scope.rglob("*") if p.is_file()]
    print("collected", len(files))

    # local import inside main to avoid E402
    repo_root = Path(__file__).resolve().parents[1]
    src_dir = repo_root / "src"
    if str(src_dir) not in sys.path:
        sys.path.insert(0, str(src_dir))
    from auditor import evidence

    start = time.time()
    zip_path, zip_sha = evidence.build_evidence_pack(
        scope, "SCOPE-TEST", files, out_dir=scope / "evidence", progress_cb=progress_cb
    )
    elapsed = time.time() - start
    print("zip", zip_path.exists(), zip_path)
    print("sha", zip_sha)
    print("elapsed", elapsed)
