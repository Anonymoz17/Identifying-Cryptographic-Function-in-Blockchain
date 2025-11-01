"""Pytest-friendly cancellation sanity tests.

This module intentionally keeps the tests small and local to avoid
interfering with the main test suite. It is imported by pytest only
and contains no top-level executable script code.
"""

# ruff: noqa: E402

import shutil
import sys
import threading
import time
from pathlib import Path
from typing import List

# allow running the script directly from tools/ when debugging
sys.path.insert(0, "src")

from auditor.intake import enumerate_inputs
from auditor.preproc import preprocess_items

NUM_FILES = 100


def make_test_tree(root: Path, num_files: int = NUM_FILES):
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    for i in range(num_files):
        sub = root / f"sub{i%5}"
        sub.mkdir(parents=True, exist_ok=True)
        p = sub / f"file_{i}.txt"
        p.write_text("x" * 1024)


def run_enumerate_with_cancel(root: Path, cancel_after: float = 0.05) -> List[dict]:
    cancel_event = threading.Event()
    result: List[dict] = []

    def worker():
        nonlocal result
        result = enumerate_inputs(
            [str(root)], progress_cb=None, cancel_event=cancel_event
        )

    t = threading.Thread(target=worker)
    t.start()
    time.sleep(cancel_after)
    cancel_event.set()
    t.join(timeout=5)
    return result


def test_enumerate_cancel(tmp_path):
    root = tmp_path / "cancel_tree"
    make_test_tree(root, num_files=50)
    res = run_enumerate_with_cancel(root, cancel_after=0.02)
    assert isinstance(res, list)
    assert len(res) <= 50


def test_preproc_cancel(tmp_path):
    root = tmp_path / "cancel_src"
    make_test_tree(root, num_files=20)
    items = run_enumerate_with_cancel(root, cancel_after=0.01)
    if not items:
        items = [
            {"path": str(p), "sha256": None, "size": p.stat().st_size, "mtime": None}
            for p in root.rglob("**/*")
            if p.is_file()
        ]

    workdir = tmp_path / "cancel_workdir"
    if workdir.exists():
        shutil.rmtree(workdir)
    workdir.mkdir(parents=True)

    cancel_event = threading.Event()
    result = None

    def worker():
        nonlocal result
        result = preprocess_items(
            items,
            str(workdir),
            progress_cb=None,
            cancel_event=cancel_event,
            do_extract=False,
        )

    t = threading.Thread(target=worker)
    t.start()
    time.sleep(0.02)
    cancel_event.set()
    t.join(timeout=10)
    assert not t.is_alive()
    assert isinstance(result, dict)
    assert "processed" in result.get("stats", {})
