"""Small benchmark to measure count_inputs and enumerate_inputs performance.

Creates a synthetic directory with many small files and times:
- count_inputs
- enumerate_inputs (which hashes files)

This helps identify whether hashing is the hotspot for large scopes.

Run: python tools/scan_benchmark.py
"""

import shutil
import sys
import time
from pathlib import Path

# ruff: noqa: E402
sys.path.insert(0, "src")

from auditor.intake import count_inputs, enumerate_inputs
from auditor.preproc import preprocess_items

TEST_DIR = Path("tools") / "_scan_test_dir"
NUM_FILES = 500


def make_test_tree():
    # remove old
    if TEST_DIR.exists():
        shutil.rmtree(TEST_DIR)
    TEST_DIR.mkdir(parents=True)
    # create some subdirs and files
    for i in range(NUM_FILES):
        sub = TEST_DIR / f"sub{i % 10}"
        sub.mkdir(parents=True, exist_ok=True)
        p = sub / f"file_{i}.txt"
        # write small content
        with p.open("w", encoding="utf-8") as f:
            f.write("hello world\n" * 10)


def time_call(fn, *args, label=None):
    t0 = time.time()
    res = fn(*args)
    t1 = time.time()
    print(f"{label or fn.__name__}: {t1-t0:.3f}s")
    return res


def main():
    print("Preparing test tree (this may take a moment)...")
    make_test_tree()
    path = str(TEST_DIR)
    print("Counting files (fast):")
    _total = time_call(count_inputs, [path], label="count_inputs")
    print("Enumerating inputs (including hashing):")
    items = time_call(enumerate_inputs, [path], None, label="enumerate_inputs")
    print(f"Enumerated {len(items)} items")
    print("Running preprocess_items (copying inputs into workdir)")
    workdir = Path("tools") / "_scan_workdir"
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)
    preproc_res = time_call(
        preprocess_items,
        items,
        str(workdir),
        None,
        label="preprocess_items",
    )
    print(
        "Preproc stats:",
        preproc_res.get("stats") if isinstance(preproc_res, dict) else preproc_res,
    )


if __name__ == "__main__":
    main()
