"""auditor.intake

Simple intake module that enumerates inputs under given paths and computes
SHA-256 hashes plus basic metadata (mtime, size). Writes `inputs.manifest.json`.

This is intentionally minimal: production code should add owners, UID/GID,
platform-specific metadata, SBOM capture hooks, and exclusion rules.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import threading
from typing import Any, Dict, List, Optional


def hash_file_sha256(
    path: str, chunk_size: int = 8192, cancel_event: Optional[threading.Event] = None
) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise OperationCancelled()
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class OperationCancelled(Exception):
    """Raised when a cooperative operation was cancelled via an Event."""


def enumerate_inputs(
    paths: List[str], progress_cb=None, cancel_event: Optional["threading.Event"] = None
) -> List[Dict[str, Any]]:  # noqa: C901 (complexity: refactor later)
    """Enumerate files and compute SHA-256.

    If progress_cb is provided it will be called as progress_cb(count, path, total)
    after each file is processed so callers can update UI or logs. If cancel_event
    is provided (a threading.Event) the function will check it periodically and
    abort early if set. This keeps long-running scans cancellable from a UI.
    """

    out: List[Dict[str, Any]] = []
    count = 0
    # Pre-count total if possible; callers can call count_inputs for a preview.
    total = None
    try:
        total = count_inputs(paths)
    except Exception:
        total = None

    for p in paths:
        # cancellation check
        if (
            cancel_event is not None
            and hasattr(cancel_event, "is_set")
            and cancel_event.is_set()
        ):
            break

        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for fn in files:
                    if cancel_event is not None and cancel_event.is_set():
                        break
                    fp = os.path.join(root, fn)
                    try:
                        stat = os.stat(fp)
                        # pass cancel_event into hashing so long files can be aborted
                        try:
                            sha = hash_file_sha256(fp, cancel_event=cancel_event)
                        except OperationCancelled:
                            # propagate cancellation to outer loop
                            raise
                        item = {
                            "path": os.path.abspath(fp),
                            "size": stat.st_size,
                            "mtime": datetime.datetime.fromtimestamp(
                                stat.st_mtime, datetime.timezone.utc
                            ).isoformat(),
                            "sha256": sha,
                        }
                        out.append(item)
                        count += 1
                        if callable(progress_cb):
                            try:
                                progress_cb(count, item["path"], total)
                            except Exception:
                                pass
                    except OperationCancelled:
                        # stop processing immediately on cancellation
                        return out
                    except Exception:
                        # skip unreadable
                        continue
                if cancel_event is not None and cancel_event.is_set():
                    break
        elif os.path.isfile(p):
            if cancel_event is not None and cancel_event.is_set():
                break
            try:
                stat = os.stat(p)
                try:
                    sha = hash_file_sha256(p, cancel_event=cancel_event)
                except OperationCancelled:
                    return out
                item = {
                    "path": os.path.abspath(p),
                    "size": stat.st_size,
                    "mtime": datetime.datetime.fromtimestamp(
                        stat.st_mtime, datetime.timezone.utc
                    ).isoformat(),
                    "sha256": sha,
                }
                out.append(item)
                count += 1
                if callable(progress_cb):
                    try:
                        progress_cb(count, item["path"], total)
                    except Exception:
                        pass
            except Exception:
                pass
    return out


def count_inputs(paths: List[str]) -> int:
    """Quickly count files under paths without hashing (fast preview)."""
    total = 0
    for p in paths:
        if os.path.isdir(p):
            for _root, _dirs, files in os.walk(p):
                total += len(files)
        elif os.path.isfile(p):
            total += 1
    return total


def count_inputs_fast(
    paths: List[str], timeout: float = 0.5, skip_dirs=None
) -> Optional[int]:
    """Attempt a faster file count using os.scandir and an optional timeout.

    - Uses iterative scandir (BFS) which is often faster than os.walk.
    - Honors a timeout (seconds). If the timeout is exceeded the function
      returns None to indicate an incomplete count (caller can fall back).
    - skip_dirs: optional iterable of directory names to skip (e.g. '.git').
    """
    if skip_dirs is None:
        skip_dirs = {
            ".git",
            "__pycache__",
            "node_modules",
            "venv",
            ".venv",
            "build",
            "dist",
        }
    else:
        skip_dirs = set(skip_dirs)

    import time
    from collections import deque

    deadline = time.time() + float(timeout)
    q = deque()
    total = 0
    for p in paths:
        q.append(p)

    try:
        while q:
            if time.time() > deadline:
                return None
            cur = q.popleft()
            try:
                if os.path.isdir(cur):
                    # scandir entries are faster than walk when there are many
                    # files because they avoid extra stat calls.
                    try:
                        with os.scandir(cur) as it:
                            for entry in it:
                                if entry.is_dir(follow_symlinks=False):
                                    if entry.name in skip_dirs:
                                        continue
                                    q.append(entry.path)
                                elif entry.is_file(follow_symlinks=False):
                                    total += 1
                    except PermissionError:
                        # skip unreadable directories
                        continue
                elif os.path.isfile(cur):
                    total += 1
            except Exception:
                # ignore transient errors on specific entries
                continue
    except Exception:
        return None
    return total


def write_manifest(manifest_path: str, items: List[Dict[str, Any]]) -> None:
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "generated_at": datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat(),
                "items": items,
            },
            f,
            indent=2,
        )


if __name__ == "__main__":
    # Demo: create manifest for current directory
    items = enumerate_inputs(["."])
    write_manifest("./case_demo/inputs.manifest.json", items)
    print("Wrote manifest with", len(items), "files")
