#!/usr/bin/env python3
"""Diagnostic: measure preprocess_items speed for a limited set of items.

Collect the first N items (compute_sha=False) from enumerate_inputs_iter and
run preprocess_items against a temporary workdir with do_extract=False and
then do_extract=True to compare times. Uses src/ on sys.path like tests.
"""
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path.cwd() / "src"))

try:
    from auditor.intake import enumerate_inputs_iter
    from auditor.preproc import preprocess_items
except Exception as e:
    print("Failed to import modules:", e)
    sys.exit(2)

SCOPE = str(Path.cwd())
LIMIT = 200

print(f"Collecting up to {LIMIT} items from scope={SCOPE} (compute_sha=False)")
items = []
start = time.time()
for i, it in enumerate(
    enumerate_inputs_iter([SCOPE], compute_sha=False, progress_cb=None)
):
    items.append(it)
    if (i + 1) >= LIMIT:
        break
collect_elapsed = time.time() - start
print(f"Collected {len(items)} items in {collect_elapsed:.2f}s")


# Helper to run a preprocess with given do_extract flag
def run_preproc(do_extract: bool):
    with tempfile.TemporaryDirectory(prefix="diag_preproc_") as td:
        wd = Path(td)
        print(f"\nRunning preprocess (do_extract={do_extract}) in {wd}")
        t0 = time.time()
        res = preprocess_items(
            items,
            str(wd),
            progress_cb=None,
            cancel_event=None,
            max_extract_depth=1,
            do_extract=do_extract,
            build_ast=False,
            build_disasm=False,
            preserve_permissions=False,
            move_extracted=False,
            stream=True,
            resume=False,
            compute_sha=False,
            copy_inputs=False,
        )
        elapsed = time.time() - t0
        print(f"Preprocess done in {elapsed:.2f}s; stats: {res.get('stats')}")
        # Show small listing of preproc dir for visibility
        pdir = wd / "preproc"
        if pdir.exists():
            count = sum(1 for _ in pdir.iterdir())
            print(f"preproc contains {count} directories/files")
        else:
            print("no preproc directory created")


# Run without extraction first
run_preproc(do_extract=False)
# Then with extraction
run_preproc(do_extract=True)

print("Diagnostic complete")
