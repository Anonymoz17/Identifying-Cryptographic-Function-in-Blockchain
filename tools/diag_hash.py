#!/usr/bin/env python3
"""Diagnostic: compare single-threaded and multi-threaded hashing speed."""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path.cwd() / "src"))
try:
    from auditor.intake import enumerate_inputs_iter
except Exception as e:
    print("Import failed:", e)
    sys.exit(2)

SCOPE = str(Path.cwd())
LIMIT = 50

for workers in (1, 4):
    print(
        f"\nRunning enumerate with compute_sha=True, hash_workers={workers}, limit={LIMIT}"
    )
    start = time.time()
    count = 0
    try:
        for it in enumerate_inputs_iter(
            [SCOPE],
            compute_sha=True,
            progress_cb=None,
            cancel_event=None,
            hash_workers=workers,
        ):
            count += 1
            if count % 10 == 0:
                print(f" Found {count}: {it.get('path')} (size={it.get('size')})")
            if count >= LIMIT:
                break
    except Exception as e:
        print("enumeration error:", e)
        raise
    elapsed = time.time() - start
    print(f"Done: {count} items in {elapsed:.2f}s ({count/elapsed:.2f} items/s)")
