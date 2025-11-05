"""Compatibility shim for `auditor.intake`.

This module re-exports (or provides) the small intake API used by older
tests and developer scripts: `enumerate_inputs`, `enumerate_inputs_iter`,
`count_inputs`, `write_manifest`, `write_manifest_iter`, `hash_file_sha256`.

It prefers to import a legacy implementation when available under
`src.auditor._legacy.intake` (keeps behavior identical). If that module is
not present it falls back to using the modern `src.auditor.setup_flow.intake`
iterator and implements a small compatibility layer (computes SHA when
requested and exposes the same function names).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterator, List, Optional

try:
    # Prefer exact legacy implementation if present (preserves old semantics)
    from src.auditor._legacy.intake import (
        enumerate_inputs,
        enumerate_inputs_iter,
        count_inputs,
        write_manifest,
        write_manifest_iter,
        hash_file_sha256,
    )
except Exception:
    # Fallback: implement thin wrappers around the new safe_enumerate
    from src.auditor.setup_flow.intake import safe_enumerate
    import os

    def hash_file_sha256(path: str, chunk_size: int = 8192, cancel_event: Optional[object] = None) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                if cancel_event is not None and getattr(cancel_event, "is_set", lambda: False)():
                    raise RuntimeError("Operation cancelled")
                chunk = fh.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()


    def enumerate_inputs_iter(paths: List[str], compute_sha: bool = True, progress_cb=None, cancel_event: Optional[object] = None, hash_workers: int = 1) -> Iterator[Dict[str, Any]]:
        # safe_enumerate yields dicts with keys 'path','relpath','size'
        for root in paths:
            for it in safe_enumerate(root):
                itm = {"path": str(it.get("path")), "size": it.get("size"), "mtime": None}
                if compute_sha:
                    try:
                        itm["sha256"] = hash_file_sha256(str(it.get("path")), cancel_event=cancel_event)
                    except Exception:
                        itm["sha256"] = None
                yield itm


    def enumerate_inputs(paths: List[str], progress_cb=None, cancel_event: Optional[object] = None, compute_sha: bool = True) -> List[Dict[str, Any]]:
        return list(enumerate_inputs_iter(paths, compute_sha=compute_sha, progress_cb=progress_cb, cancel_event=cancel_event))


    def count_inputs(paths: List[str]) -> int:
        total = 0
        for root in paths:
            for _ in safe_enumerate(root):
                total += 1
        return total


    def write_manifest(manifest_path: str, items: List[Dict[str, Any]]) -> None:
        p = manifest_path
        # preserve the older JSON-single-document behavior when suffix is .json
        try:
            write_json_wrapper = str(manifest_path).lower().endswith(".json")
        except Exception:
            write_json_wrapper = False
        if write_json_wrapper:
            doc = {"generated_at": None, "items": []}
            for it in items:
                try:
                    doc["items"].append(it)
                except Exception:
                    continue
            with open(p, "w", encoding="utf-8") as f:
                f.write(json.dumps(doc, sort_keys=True, ensure_ascii=False))
        else:
            with open(p, "w", encoding="utf-8") as f:
                for it in items:
                    try:
                        f.write(json.dumps(it, sort_keys=True, ensure_ascii=False) + "\n")
                    except Exception:
                        continue


    def write_manifest_iter(manifest_path: str, items_iter, flush: bool = True) -> None:
        p = manifest_path
        open(p, "w", encoding="utf-8").close()
        with open(p, "w", encoding="utf-8") as f:
            for it in items_iter:
                try:
                    f.write(json.dumps(it, sort_keys=True, ensure_ascii=False) + "\n")
                    if flush:
                        try:
                            f.flush()
                        except Exception:
                            pass
                except Exception:
                    continue

__all__ = [
    "enumerate_inputs",
    "enumerate_inputs_iter",
    "count_inputs",
    "write_manifest",
    "write_manifest_iter",
    "hash_file_sha256",
]
