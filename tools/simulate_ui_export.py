"""Simulate the Auditor UI export flow for a given workspace directory.

This script uses the same Workspace and build_evidence_pack code and prints
progress updates similar to what the UI would display.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path


def progress_cb(i, total):
    frac = float(i) / float(total) if total and total > 0 else 0.0
    print(f"{time.strftime('%H:%M:%S')} - progress {i}/{total} ({frac:.1%})")


if __name__ == "__main__":
    repo = Path(__file__).resolve().parents[1]
    if str(repo) not in sys.path:
        sys.path.insert(0, str(repo))

    from auditor.evidence import build_evidence_pack
    from auditor.workspace import Workspace

    ws = Workspace(Path("tools"), "sample_scope")
    ws.ensure()
    scope_dir = Path("tools/sample_scope").resolve()
    # collect files
    files = [p for p in scope_dir.rglob("*") if p.is_file()]
    print("collected", len(files), "files")
    cancel = threading.Event()
    start = time.time()
    zip_path, sha = build_evidence_pack(
        scope_dir,
        "SAMPLE",
        files,
        out_dir=scope_dir / "evidence",
        progress_cb=progress_cb,
        cancel_event=cancel,
    )
    print("done in", time.time() - start)
    print("zip", zip_path)
    print("sha", sha)
