"""auditor.preproc

Minimal preprocessing scaffold (stage 2).
"""

from __future__ import annotations

import datetime
import json
import shutil
import threading
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


def _atomic_write(path: Path, data: str) -> None:
    """Write data to a temporary file and rename into place.

    This avoids partial writes when multiple processes/threads are involved.
    """
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data, encoding="utf-8")
    tmp.replace(path)


def preprocess_items(
    items: List[Dict[str, Any]],
    workdir: str,
    progress_cb: Optional[Callable[[int, int], None]] = None,
    cancel_event: Optional[threading.Event] = None,
) -> List[Dict[str, Any]]:  # noqa: C901 (complexity; split into helpers later)
    """Process items and write per-file artifacts.

    progress_cb, if provided, will be called as progress_cb(processed_count, total)
    after each item is completed. If cancel_event is set the function will stop
    early and return the index entries created up to that point.

    Returns list of index entries written to preproc.index.jsonl.
    """

    wd = Path(workdir)
    preproc_dir = wd / "preproc"
    preproc_dir.mkdir(parents=True, exist_ok=True)
    index_path = wd / "preproc.index.jsonl"
    index_entries: List[Dict[str, Any]] = []

    total = len(items)
    processed = 0

    for it in items:
        if cancel_event is not None and cancel_event.is_set():
            break

        sha = it.get("sha256")
        if not sha:
            processed += 1
            if callable(progress_cb):
                try:
                    progress_cb(processed, total)
                except Exception:
                    pass
            continue

        # deterministic artifact dir per sha
        art_dir = preproc_dir / sha
        art_dir.mkdir(parents=True, exist_ok=True)

        src = it.get("path")
        if not src or not Path(src).exists():
            processed += 1
            if callable(progress_cb):
                try:
                    progress_cb(processed, total)
                except Exception:
                    pass
            continue

        # copy the original file as input.bin if not present
        dst_input = art_dir / "input.bin"
        try:
            if not dst_input.exists():
                shutil.copy2(str(src), str(dst_input))
        except Exception:
            # skip on copy failure; continue to write metadata
            pass

        # normalize mtime: tests and upstream code sometimes provide numeric
        # timestamps (float/int) while other callers use ISO strings. Keep a
        # consistent ISO8601 string in metadata.json.
        raw_mtime = it.get("mtime")
        if isinstance(raw_mtime, (int, float)):
            try:
                mtime_val = datetime.datetime.fromtimestamp(
                    float(raw_mtime), datetime.timezone.utc
                ).isoformat()
            except Exception:
                mtime_val = str(raw_mtime)
        else:
            mtime_val = raw_mtime

        meta = {
            "path": str(Path(src).resolve()),
            "sha256": sha,
            "size": it.get("size"),
            "mtime": mtime_val,
            # store artifact_dir as a POSIX-style relative path for
            # cross-platform consistency (index files are easier to parse)
            "artifact_dir": art_dir.relative_to(wd).as_posix(),
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }

        meta_path = art_dir / "metadata.json"
        try:
            _atomic_write(meta_path, json.dumps(meta, sort_keys=True, indent=2))
        except Exception:
            # best-effort
            pass

        idx = {
            "input_path": str(Path(src).resolve()),
            "sha256": sha,
            "size": it.get("size"),
            "artifact_dir": art_dir.relative_to(wd).as_posix(),
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        index_entries.append(idx)

        # append to index file (ndjson)
        try:
            with index_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(idx, sort_keys=True, ensure_ascii=False) + "\n")
        except Exception:
            pass

        processed += 1
        if callable(progress_cb):
            try:
                progress_cb(processed, total)
            except Exception:
                pass

    return index_entries


if __name__ == "__main__":
    print("preproc module: call preprocess_items(items, workdir)")
