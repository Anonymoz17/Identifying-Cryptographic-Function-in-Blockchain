"""auditor.intake

Simple intake module that enumerates inputs under given paths and computes
SHA-256 hashes plus basic metadata (mtime, size). Writes `inputs.manifest.json`.

This is intentionally minimal: production code should add owners, UID/GID,
platform-specific metadata, SBOM capture hooks, and exclusion rules.
"""

from __future__ import annotations

import datetime
import fnmatch
import hashlib
import json
import os
import threading
from typing import Any, Dict, Iterable, List, Optional


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


def _matches_filters(
    path: str,
    root: str,
    include_globs: Optional[Iterable[str]] = None,
    exclude_globs: Optional[Iterable[str]] = None,
) -> bool:
    """Return True if the path should be INCLUDED according to the provided
    include/exclude glob lists. Matching is attempted against the path relative
    to the provided root and the basename to give flexible matches.
    """
    try:
        rel = os.path.relpath(path, root)
    except Exception:
        rel = path
    name = os.path.basename(path)

    # Exclude has precedence: if any exclude matches, skip
    if exclude_globs:
        for g in exclude_globs:
            g = g.strip()
            if not g:
                continue
            if fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(name, g):
                return False

    # If includes are provided, require at least one to match
    if include_globs:
        for g in include_globs:
            g = g.strip()
            if not g:
                continue
            if fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(name, g):
                return True
        # none matched -> exclude
        return False

    # no include list means include by default
    return True


def enumerate_inputs(
    paths: List[str],
    progress_cb=None,
    cancel_event: Optional["threading.Event"] = None,
    include_globs: Optional[Iterable[str]] = None,
    exclude_globs: Optional[Iterable[str]] = None,
    max_file_size_bytes: Optional[int] = None,
    follow_symlinks: bool = False,
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
        total = count_inputs(
            paths,
            include_globs=include_globs,
            exclude_globs=exclude_globs,
            max_file_size_bytes=max_file_size_bytes,
            follow_symlinks=follow_symlinks,
        )
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
            for root, _dirs, files in os.walk(p, followlinks=follow_symlinks):
                for fn in files:
                    if cancel_event is not None and cancel_event.is_set():
                        break
                    fp = os.path.join(root, fn)
                    try:
                        # Optionally stat following or not following symlinks
                        stat = os.stat(fp, follow_symlinks=follow_symlinks)
                        if (
                            max_file_size_bytes is not None
                            and stat.st_size > max_file_size_bytes
                        ):
                            # skip large files
                            continue
                        # apply include/exclude filters (relative to the path root)
                        if not _matches_filters(fp, p, include_globs, exclude_globs):
                            continue
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
                stat = os.stat(p, follow_symlinks=follow_symlinks)
                if (
                    max_file_size_bytes is not None
                    and stat.st_size > max_file_size_bytes
                ):
                    continue
                if not _matches_filters(p, p, include_globs, exclude_globs):
                    continue
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


def count_inputs(
    paths: List[str],
    include_globs: Optional[Iterable[str]] = None,
    exclude_globs: Optional[Iterable[str]] = None,
    max_file_size_bytes: Optional[int] = None,
    follow_symlinks: bool = False,
) -> int:
    """Quickly count files under paths without hashing (fast preview).

    This honors the same filters as enumerate_inputs when provided.
    """
    total = 0
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p, followlinks=follow_symlinks):
                for fn in files:
                    fp = os.path.join(root, fn)
                    try:
                        stat = os.stat(fp, follow_symlinks=follow_symlinks)
                        if (
                            max_file_size_bytes is not None
                            and stat.st_size > max_file_size_bytes
                        ):
                            continue
                        if not _matches_filters(fp, p, include_globs, exclude_globs):
                            continue
                        total += 1
                    except Exception:
                        continue
        elif os.path.isfile(p):
            try:
                stat = os.stat(p, follow_symlinks=follow_symlinks)
                if (
                    max_file_size_bytes is not None
                    and stat.st_size > max_file_size_bytes
                ):
                    continue
                if not _matches_filters(p, p, include_globs, exclude_globs):
                    continue
                total += 1
            except Exception:
                pass
    return total


def count_inputs_fast(
    paths: List[str],
    timeout: float = 0.5,
    skip_dirs=None,
    include_globs: Optional[Iterable[str]] = None,
    exclude_globs: Optional[Iterable[str]] = None,
    max_file_size_bytes: Optional[int] = None,
    follow_symlinks: bool = False,
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
                                if time.time() > deadline:
                                    return None
                                try:
                                    if entry.is_dir(follow_symlinks=follow_symlinks):
                                        if entry.name in skip_dirs:
                                            continue
                                        q.append(entry.path)
                                    elif entry.is_file(follow_symlinks=follow_symlinks):
                                        # optional size filter
                                        try:
                                            if max_file_size_bytes is not None:
                                                st = entry.stat(
                                                    follow_symlinks=follow_symlinks
                                                )
                                                if st.st_size > max_file_size_bytes:
                                                    continue
                                        except Exception:
                                            # if stat fails, count conservatively
                                            pass
                                        # apply include/exclude filters
                                        try:
                                            if not _matches_filters(
                                                entry.path,
                                                cur,
                                                include_globs,
                                                exclude_globs,
                                            ):
                                                continue
                                        except Exception:
                                            pass
                                        total += 1
                                except Exception:
                                    continue
                    except PermissionError:
                        # skip unreadable directories
                        continue
                elif os.path.isfile(cur):
                    try:
                        st = os.stat(cur, follow_symlinks=follow_symlinks)
                        if (
                            max_file_size_bytes is not None
                            and st.st_size > max_file_size_bytes
                        ):
                            continue
                        if not _matches_filters(cur, cur, include_globs, exclude_globs):
                            continue
                        total += 1
                    except Exception:
                        pass
            except Exception:
                # ignore transient errors on specific entries
                continue
    except Exception:
        return None
    return total


def estimate_disk_usage(
    paths: List[str],
    sample_limit: int = 200,
    follow_symlinks: bool = False,
    include_globs: Optional[Iterable[str]] = None,
    exclude_globs: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Estimate disk usage by sampling up to `sample_limit` files.

    Returns a dict with keys:
      - sampled_files: int
      - sampled_bytes: int
      - sample_limit: int
      - top_dirs: Dict[str, int]  (approx bytes per top-level dir seen in sample)

    This is intentionally lightweight and best-effort: it walks breadth-first
    and stops after `sample_limit` files have been stat'd. It honors the
    include/exclude globs and follow_symlinks flag similarly to other intake
    functions.
    """
    from collections import defaultdict, deque

    q = deque()
    for p in paths:
        q.append(p)

    seen = 0
    total_size = 0
    top_dirs: Dict[str, int] = defaultdict(int)

    while q and seen < int(sample_limit):
        cur = q.popleft()
        try:
            if os.path.isdir(cur):
                try:
                    with os.scandir(cur) as it:
                        for entry in it:
                            if seen >= sample_limit:
                                break
                            try:
                                if entry.is_file(follow_symlinks=follow_symlinks):
                                    try:
                                        st = entry.stat(follow_symlinks=follow_symlinks)
                                    except Exception:
                                        continue
                                    # apply filters
                                    # (no size-limit check here; estimator focuses on sample stats)
                                    if not _matches_filters(
                                        entry.path, cur, include_globs, exclude_globs
                                    ):
                                        continue
                                    seen += 1
                                    total_size += st.st_size
                                    # compute top-level directory relative to cur
                                    try:
                                        rel = os.path.relpath(entry.path, cur)
                                        first = rel.split(os.sep)[0]
                                    except Exception:
                                        first = os.path.basename(cur) or cur
                                    top_dirs[first] += st.st_size
                                elif entry.is_dir(follow_symlinks=follow_symlinks):
                                    q.append(entry.path)
                            except Exception:
                                continue
                except PermissionError:
                    continue
            elif os.path.isfile(cur):
                try:
                    st = os.stat(cur, follow_symlinks=follow_symlinks)
                    if not _matches_filters(cur, cur, include_globs, exclude_globs):
                        continue
                    seen += 1
                    total_size += st.st_size
                    top_dirs[os.path.basename(cur) or cur] += st.st_size
                except Exception:
                    pass
        except Exception:
            continue

    return {
        "sampled_files": seen,
        "sampled_bytes": total_size,
        "sample_limit": int(sample_limit),
        "top_dirs": dict(
            sorted(top_dirs.items(), key=lambda kv: kv[1], reverse=True)[:16]
        ),
    }


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
