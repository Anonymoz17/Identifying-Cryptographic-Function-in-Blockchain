"""Test cancellation of build_evidence_pack: start packaging and cancel after delay."""

import sys
import threading
import time
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
if str(repo) not in sys.path:
    sys.path.insert(0, str(repo))


scope = Path("tools/huge_scope").resolve()
files = [p for p in scope.rglob("*") if p.is_file()]
print("collected", len(files))

cancel = threading.Event()


def run_pack():
    try:
        # local import here to avoid E402 at module import time
        from auditor import evidence

        zip_path, sha = evidence.build_evidence_pack(
            scope,
            "CANCEL-TEST",
            files,
            out_dir=scope / "evidence",
            cancel_event=cancel,
            progress_step=max(1, len(files) // 100),
        )
        print("completed", zip_path)
    except Exception as e:
        print("pack error", e)


thr = threading.Thread(target=run_pack, daemon=True)
thr.start()
# wait a short while then cancel
time.sleep(0.5)
print("requesting cancel")
cancel.set()
thr.join()

# check for partial zip
evidence_dir = scope / "evidence"
if evidence_dir.exists():
    zips = list(evidence_dir.glob("*.zip"))
    print("zips after cancel", len(zips))
else:
    print("no evidence dir")
