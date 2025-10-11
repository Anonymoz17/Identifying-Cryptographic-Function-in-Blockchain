"""auditor.intake

Simple intake module that enumerates inputs under given paths and computes
SHA-256 hashes plus basic metadata (mtime, size). Writes `inputs.manifest.json`.

This is intentionally minimal: production code should add owners, UID/GID,
platform-specific metadata, SBOM capture hooks, and exclusion rules.
"""
from __future__ import annotations

import os
import json
import hashlib
import datetime
from typing import List, Dict, Any


def hash_file_sha256(path: str, chunk_size: int = 8192) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def enumerate_inputs(paths: List[str], progress_cb=None) -> List[Dict[str, Any]]:
    """Enumerate files and compute SHA-256.

    If progress_cb is provided it will be called as progress_cb(count, path)
    after each file is processed so callers can update UI or logs.
    """
    out: List[Dict[str, Any]] = []
    count = 0
    for p in paths:
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for fn in files:
                    fp = os.path.join(root, fn)
                    try:
                        stat = os.stat(fp)
                        sha = hash_file_sha256(fp)
                        item = {
                            'path': os.path.abspath(fp),
                            'size': stat.st_size,
                            'mtime': datetime.datetime.utcfromtimestamp(stat.st_mtime).isoformat() + 'Z',
                            'sha256': sha,
                        }
                        out.append(item)
                        count += 1
                        if callable(progress_cb):
                            try:
                                progress_cb(count, item['path'])
                            except Exception:
                                pass
                    except Exception:
                        # skip unreadable
                        continue
        elif os.path.isfile(p):
            try:
                stat = os.stat(p)
                sha = hash_file_sha256(p)
                item = {
                    'path': os.path.abspath(p),
                    'size': stat.st_size,
                    'mtime': datetime.datetime.utcfromtimestamp(stat.st_mtime).isoformat() + 'Z',
                    'sha256': sha,
                }
                out.append(item)
                count += 1
                if callable(progress_cb):
                    try:
                        progress_cb(count, item['path'])
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


def write_manifest(manifest_path: str, items: List[Dict[str, Any]]) -> None:
    with open(manifest_path, 'w', encoding='utf-8') as f:
        json.dump({'generated_at': datetime.datetime.utcnow().isoformat() + 'Z', 'items': items}, f, indent=2)


if __name__ == '__main__':
    # Demo: create manifest for current directory
    items = enumerate_inputs(['.'])
    write_manifest('./case_demo/inputs.manifest.json', items)
    print('Wrote manifest with', len(items), 'files')
