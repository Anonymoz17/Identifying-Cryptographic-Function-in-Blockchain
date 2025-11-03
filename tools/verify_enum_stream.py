"""Verify streaming enumeration and manifest writing on a large scope.

This script performs a fast-scan (no hashing) enumerate_inputs_iter over the
repo root and writes items into tools/verify_inputs.manifest.ndjson, flushing
after each line. It also starts a background count worker to estimate total and
prints ETA/files-per-second.

Run from repo root: python tools/verify_enum_stream.py
"""

import json
import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, "src")
from auditor.intake import count_inputs, enumerate_inputs_iter  # noqa: E402

SCOPE = os.getcwd()
MANIFEST = Path("tools") / "verify_inputs.manifest.ndjson"

# background estimate
_total_est = None


def count_worker():
    global _total_est
    try:
        _total_est = count_inputs([SCOPE])
    except Exception:
        _total_est = None


# start count thread
ct = threading.Thread(target=count_worker, daemon=True)
ct.start()

last = 0
start = time.time()

# ensure parent exists
MANIFEST.parent.mkdir(parents=True, exist_ok=True)
with MANIFEST.open("w", encoding="utf-8") as mf:
    try:
        gen = enumerate_inputs_iter([SCOPE], compute_sha=False, progress_cb=None)
    except Exception as e:
        print("failed to create iterator:", e)
        raise
    count = 0
    for item in gen:
        count += 1
        now = time.time()
        elapsed = now - start
        rate = count / elapsed if elapsed > 0 else 0.0
        est = _total_est if _total_est else "unknown"
        eta = "unknown"
        try:
            if isinstance(_total_est, int) and rate > 0:
                eta = int(max(0, (_total_est - count) / rate))
        except Exception:
            eta = "unknown"
        p = item.get("path")
        short = p
        if p and len(p) > 140:
            short = "..." + p[-137:]
        print(f"Found: {short}")
        print(f"Enumerating {count}/{est} ({rate:.1f}/s) ETA: {eta}s")
        try:
            mf.write(json.dumps(item, ensure_ascii=False) + "\n")
            mf.flush()
            try:
                os.fsync(mf.fileno())
            except Exception:
                pass
        except Exception as e:
            print("write error", e)
        if count >= 50:
            print("Stopping after 50 items for verification")
            break

print("Done. Manifest written to", str(MANIFEST))
print("Manifest size (lines):", sum(1 for _ in MANIFEST.open("r", encoding="utf-8")))
