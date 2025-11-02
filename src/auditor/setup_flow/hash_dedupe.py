from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Dict, Iterator, Optional

from .setupmessages import Notifier
from .persistence import NDJSONBufferedWriter


def compute_sha256(path: Path, chunk_size: int = 8192) -> str:
    """Compute SHA-256 of a file by streaming its contents.

    Returns hex digest. Raises exceptions on unreadable files.
    """
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


class HasherDedupe:
    """Process a stream of items, compute SHA-256, and optionally skip duplicates.

    Items expected to be dict-like and include a 'path' key (Path or str).

    Usage:
      hd = HasherDedupe(notifier=Notifier())
      for item in hd.process(items_iter):
          # item contains 'sha256' and 'dedup_first' (bool)

    After processing, inspect hd.hash_map for hash->first_path mapping and
    hd.stats for counters.
    """

    def __init__(self, notifier: Optional[Notifier] = None, chunk_size: int = 8192, skip_duplicates: bool = True):
        self.notifier = notifier or Notifier()
        self.chunk_size = chunk_size
        self.skip_duplicates = skip_duplicates
        self.hash_map: Dict[str, str] = {}
        self.stats = {"processed": 0, "duplicates": 0, "errors": 0}
        # optional NDJSON writer for dedupe events
        self._dedupe_writer: Optional[NDJSONBufferedWriter] = None

    def attach_dedupe_writer(self, path_or_writer):
        """Attach a dedupe NDJSON writer.

        Accepts either a Path/str to create an NDJSONBufferedWriter, or an
        existing NDJSONBufferedWriter instance.
        """
        try:
            if isinstance(path_or_writer, NDJSONBufferedWriter):
                self._dedupe_writer = path_or_writer
            else:
                self._dedupe_writer = NDJSONBufferedWriter(Path(path_or_writer), flush_every=20)
        except Exception:
            self._dedupe_writer = None

    def flush_dedupe(self):
        try:
            if self._dedupe_writer is not None:
                self._dedupe_writer.flush()
        except Exception:
            pass

    def process(self, items: Iterator[dict]) -> Iterator[dict]:
        for it in items:
            try:
                p = it.get("path")
                if p is None:
                    self.notifier.warn("Item missing path; skipping", details={"item": it})
                    self.stats["errors"] += 1
                    continue
                path = Path(p)
                if not path.exists() or not path.is_file():
                    self.notifier.warn("Path not a regular file; skipping", path=str(path))
                    self.stats["errors"] += 1
                    continue

                t0 = time.time()
                try:
                    h = compute_sha256(path, chunk_size=self.chunk_size)
                except Exception as e:
                    self.notifier.warn("Could not hash file; skipping", path=str(path), details={"error": str(e)})
                    self.stats["errors"] += 1
                    continue
                took = time.time() - t0

                it["sha256"] = h
                it["hash_time_s"] = took

                if h in self.hash_map:
                    # duplicate
                    orig = self.hash_map[h]
                    self.stats["duplicates"] += 1
                    self.notifier.skip("Duplicate file (by hash)", path=str(path), details={"sha256": h, "original": orig})
                    # write dedupe event if writer attached
                    try:
                        if self._dedupe_writer is not None:
                            self._dedupe_writer.write({"sha256": h, "path": str(path), "original": orig})
                    except Exception:
                        pass
                    if self.skip_duplicates:
                        continue
                    else:
                        it["dedup_first"] = False
                        it["dedup_original"] = orig
                else:
                    # first time we've seen this hash
                    self.hash_map[h] = str(path)
                    it["dedup_first"] = True
                    self.stats["processed"] += 1
                    self.notifier.ok("File hashed", path=str(path), details={"sha256": h, "time_s": took})

                yield it
            except Exception as e:
                self.notifier.warn("Unhandled error in hashing step; skipping item", details={"error": str(e), "item": repr(it)})
                self.stats["errors"] += 1
                continue
