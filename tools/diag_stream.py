#!/usr/bin/env python3
"""Diagnostic: enumerate first N items from enumerate_inputs_iter and report timing.

Run from repository root. This script adds src/ to sys.path so imports work like tests.
"""
import sys
import time
from pathlib import Path

# Make sure the library imports find the package under src/
sys.path.insert(0, str(Path.cwd() / "src"))

try:
    from auditor.intake import enumerate_inputs_iter
except Exception as e:
    print("Failed to import enumerate_inputs_iter:", e)
    sys.exit(2)

SCOPE = str(Path.cwd())
LIMIT = 100

print(f"Diagnostic enumerate: scope={SCOPE!r}, limit={LIMIT}, compute_sha=False")
start = time.time()
count = 0
last_print = start
try:
    it = enumerate_inputs_iter([SCOPE], compute_sha=False, progress_cb=None)
    for item in it:
        count += 1
        # print a short progress every 10 items
        if count % 10 == 0:
            now = time.time()
            print(
                f"Found {count} items so far (last: {item.get('path')}) - elapsed {now - start:.2f}s"
            )
            last_print = now
        if count >= LIMIT:
            break
except KeyboardInterrupt:
    print("Interrupted by user")
except Exception as e:
    print("enumeration raised exception:", e)
    raise
finally:
    elapsed = time.time() - start
    rate = count / elapsed if elapsed > 0 else 0.0
    print(f"Done: found {count} items in {elapsed:.2f}s ({rate:.2f} items/s)")
