"""Quick benchmark script for intake.enumerate_inputs and iterate variants.
Creates N small files and measures time for listing (no hash) and hashing modes.
"""

# ruff: noqa: E402

import argparse
import os
import sys
import time
from pathlib import Path

# Ensure local src/ is on sys.path so `auditor` package can be imported when
# running this script directly.
sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
)
from auditor import intake


def make_files(path: Path, n: int):
    path.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (path / f"f{i}.txt").write_text(str(i))


def run(path: Path, n: int):
    make_files(path, n)
    p = str(path)
    print("Files:", n)
    t0 = time.time()
    items = intake.enumerate_inputs([p], compute_sha=False)
    t1 = time.time()
    print("enumerate no-hash: {:.3f}s, items:".format(t1 - t0), len(items))

    t0 = time.time()
    # only measure hashing on a smaller sample to keep time reasonable
    items_h = intake.enumerate_inputs([p], compute_sha=True)
    t1 = time.time()
    print("enumerate with-hash: {:.3f}s, items:".format(t1 - t0), len(items_h))

    # iterator-based (no hash)
    t0 = time.time()
    cnt = 0
    for _ in intake.enumerate_inputs_iter([p], compute_sha=False):
        cnt += 1
    t1 = time.time()
    print("iter no-hash: {:.3f}s, items:".format(t1 - t0), cnt)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--n", type=int, default=2000)
    parser.add_argument("--dir", type=str, default="tools/tmp_bench")
    args = parser.parse_args()
    run(Path(args.dir), args.n)
