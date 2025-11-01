"""auditor.intake

Simple intake module that enumerates inputs under given paths and computes
SHA-256 hashes plus basic metadata (mtime, size). Writes `inputs.manifest.json`.

This is intentionally minimal: production code should add owners, UID/GID,
platform-specific metadata, SBOM capture hooks, and exclusion rules.
"""

from __future__ import annotations

import concurrent.futures
import datetime
import hashlib
import json
import logging
import os
import threading
import time
from typing import Any, Dict, Iterator, List, Optional

logger = logging.getLogger(__name__)


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
    paths: List[str],
    progress_cb=None,
    cancel_event: Optional["threading.Event"] = None,
    compute_sha: bool = True,
) -> List[Dict[str, Any]]:  # noqa: C901 (complexity: refactor later)
    """Enumerate files and compute SHA-256.

    If progress_cb is provided it will be called as progress_cb(count, path, total)
    after each file is processed so callers can update UI or logs. If cancel_event
    is provided (a threading.Event) the function will check it periodically and
    abort early if set. This keeps long-running scans cancellable from a UI.
    """

    # Backwards-compatible: implement enumerate_inputs using the iterator
    return list(
        enumerate_inputs_iter(
            paths,
            compute_sha=compute_sha,
            progress_cb=progress_cb,
            cancel_event=cancel_event,
        )
    )


def enumerate_inputs_iter(
    paths: List[str],
    compute_sha: bool = True,
    progress_cb=None,
    cancel_event: Optional["threading.Event"] = None,
    hash_workers: int = 1,
) -> Iterator[Dict[str, Any]]:
    """Iterator variant of enumerate_inputs.

    Yields items as they are discovered. If compute_sha is False this
    function will skip expensive hashing and only yield path/size/mtime.
    The iterator stops early if cancel_event is set.

    If hash_workers > 1 and compute_sha is True, a small thread pool is
    used to compute SHA hashes concurrently to improve throughput on
    multi-core/IO-heavy systems.
    """
    count = 0
    total = None

    # If requested, run hashing in a small thread pool and stream results
    if compute_sha and hash_workers and hash_workers > 1:
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=hash_workers
        ) as executor:
            pending: List[tuple[concurrent.futures.Future, Dict[str, Any]]] = []

            def _drain_completed(pending_list):
                # collect and yield completed futures (as they finish)
                for fut, itm in list(pending_list):
                    if fut.done():
                        try:
                            sha = fut.result()
                            itm["sha256"] = sha
                        except Exception:
                            pass
                        pending_list.remove((fut, itm))
                        yield itm

            for root_path in paths:
                if (
                    cancel_event is not None
                    and hasattr(cancel_event, "is_set")
                    and cancel_event.is_set()
                ):
                    break

                if os.path.isdir(root_path):
                    for root, _dirs, files in os.walk(root_path):
                        for fn in files:
                            if cancel_event is not None and cancel_event.is_set():
                                break
                            fp = os.path.join(root, fn)
                            try:
                                stat = os.stat(fp)
                                item = {
                                    "path": os.path.abspath(fp),
                                    "size": stat.st_size,
                                    "mtime": datetime.datetime.fromtimestamp(
                                        stat.st_mtime, datetime.timezone.utc
                                    ).isoformat(),
                                }
                                # submit hashing job
                                fut = executor.submit(
                                    hash_file_sha256, fp, 8192, cancel_event
                                )
                                pending.append((fut, item))
                                # if we've filled the pipeline, wait for one to finish
                                if len(pending) >= hash_workers:
                                    concurrent.futures.wait(
                                        [f for f, _ in pending],
                                        return_when=concurrent.futures.FIRST_COMPLETED,
                                    )
                                    for itm in _drain_completed(pending):
                                        count += 1
                                        if callable(progress_cb):
                                            try:
                                                progress_cb(count, itm["path"], total)
                                            except Exception:
                                                pass
                                        yield itm
                            except Exception:
                                continue
                        if cancel_event is not None and cancel_event.is_set():
                            break
                elif os.path.isfile(root_path):
                    if cancel_event is not None and cancel_event.is_set():
                        break
                    try:
                        stat = os.stat(root_path)
                        item = {
                            "path": os.path.abspath(root_path),
                            "size": stat.st_size,
                            "mtime": datetime.datetime.fromtimestamp(
                                stat.st_mtime, datetime.timezone.utc
                            ).isoformat(),
                        }
                        fut = executor.submit(
                            hash_file_sha256, root_path, 8192, cancel_event
                        )
                        pending.append((fut, item))
                        if len(pending) >= hash_workers:
                            concurrent.futures.wait(
                                [f for f, _ in pending],
                                return_when=concurrent.futures.FIRST_COMPLETED,
                            )
                            for itm in _drain_completed(pending):
                                count += 1
                                if callable(progress_cb):
                                    try:
                                        progress_cb(count, itm["path"], total)
                                    except Exception:
                                        pass
                                yield itm
                    except Exception:
                        pass

            # drain remaining futures
            while pending:
                concurrent.futures.wait(
                    [f for f, _ in pending],
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for itm in _drain_completed(pending):
                    count += 1
                    if callable(progress_cb):
                        try:
                            progress_cb(count, itm["path"], total)
                        except Exception:
                            pass
                    yield itm

            return

    # Fallback: single-threaded (original) behavior
    for p in paths:
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
                        item = {
                            "path": os.path.abspath(fp),
                            "size": stat.st_size,
                            "mtime": datetime.datetime.fromtimestamp(
                                stat.st_mtime, datetime.timezone.utc
                            ).isoformat(),
                        }
                        if compute_sha:
                            t0 = time.time()
                            try:
                                sha = hash_file_sha256(fp, cancel_event=cancel_event)
                            except OperationCancelled:
                                # cooperative cancellation: stop iteration
                                return
                            took = time.time() - t0
                            if logger.isEnabledFor(logging.DEBUG):
                                logger.debug("hashed %s in %.3fs", fp, took)
                            item["sha256"] = sha
                        count += 1
                        if callable(progress_cb):
                            try:
                                progress_cb(count, item["path"], total)
                            except Exception:
                                pass
                        yield item
                    except OperationCancelled:
                        return
                    except Exception:
                        # unreadable or transient – skip
                        continue
                if cancel_event is not None and cancel_event.is_set():
                    break
        elif os.path.isfile(p):
            if cancel_event is not None and cancel_event.is_set():
                break
            try:
                stat = os.stat(p)
                item = {
                    "path": os.path.abspath(p),
                    "size": stat.st_size,
                    "mtime": datetime.datetime.fromtimestamp(
                        stat.st_mtime, datetime.timezone.utc
                    ).isoformat(),
                }
                if compute_sha:
                    t0 = time.time()
                    try:
                        sha = hash_file_sha256(p, cancel_event=cancel_event)
                    except OperationCancelled:
                        return
                    took = time.time() - t0
                    if logger.isEnabledFor(logging.DEBUG):
                        logger.debug("hashed %s in %.3fs", p, took)
                    item["sha256"] = sha
                count += 1
                if callable(progress_cb):
                    try:
                        progress_cb(count, item["path"], total)
                    except Exception:
                        pass
                yield item
            except OperationCancelled:
                return
            except Exception:
                pass


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


def write_manifest(manifest_path: str, items: List[Dict[str, Any]]) -> None:
    """Write manifest.

    Backwards compatibility: when the target path has a `.json` suffix we
    write a single JSON object with keys `generated_at` and `items` (this is
    what older callers and tests expect). When the target has a `.ndjson` or
    `.jsonl` suffix (or any other non-.json suffix) we write NDJSON (one JSON
    object per line) which is streaming-friendly.
    """
    # Write to a temporary file then replace atomically to avoid partial writes
    from pathlib import Path

    p = Path(manifest_path)
    tmp = p.with_suffix(p.suffix + ".tmp")
    write_json_wrapper = False
    try:
        write_json_wrapper = str(manifest_path).lower().endswith(".json")
    except Exception:
        write_json_wrapper = False

    if write_json_wrapper:
        # write a single JSON document compatible with older tests/tools
        doc = {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "items": [],
        }
        for it in items:
            try:
                doc["items"].append(it)
            except Exception:
                continue
        try:
            with tmp.open("w", encoding="utf-8") as f:
                f.write(json.dumps(doc, sort_keys=True, ensure_ascii=False))
        except Exception:
            pass
    else:
        with tmp.open("w", encoding="utf-8") as f:
            for it in items:
                try:
                    f.write(json.dumps(it, sort_keys=True, ensure_ascii=False) + "\n")
                except Exception:
                    # best-effort: skip items that cannot be serialized
                    continue
    try:
        tmp.replace(p)
    except Exception:
        # fallback: try a simple rename
        try:
            tmp.rename(p)
        except Exception:
            # as a last resort, write directly
            with p.open("w", encoding="utf-8") as f:
                for it in items:
                    try:
                        f.write(
                            json.dumps(it, sort_keys=True, ensure_ascii=False) + "\n"
                        )
                    except Exception:
                        continue


def write_manifest_iter(manifest_path: str, items_iter, flush: bool = True) -> None:
    """Write NDJSON lines incrementally as items arrive from an iterator.

    This function opens the target manifest file and writes each item as a
    separate JSON line. It flushes after each line to make the file readable
    by other processes while still being written.
    """
    from pathlib import Path

    p = Path(manifest_path)
    # Ensure parent exists
    p.parent.mkdir(parents=True, exist_ok=True)
    # Open for writing (truncate) and stream lines as they arrive.
    # Batch flush every N lines to reduce expensive syscalls (fsync) on some
    # platforms (Windows), which can make streaming appear to stall.
    batch_flush = 20
    written = 0
    with p.open("w", encoding="utf-8") as f:
        for it in items_iter:
            try:
                f.write(json.dumps(it, sort_keys=True, ensure_ascii=False) + "\n")
                written += 1
                if flush and (written % batch_flush) == 0:
                    try:
                        f.flush()
                    except Exception:
                        pass
            except Exception:
                # skip serialization errors
                continue


if __name__ == "__main__":
    # Demo: create manifest for current directory
    items = enumerate_inputs(["."])
    write_manifest("./case_demo/inputs.manifest.json", items)
    print("Wrote manifest with", len(items), "files")
