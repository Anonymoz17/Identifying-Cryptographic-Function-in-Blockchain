from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, Optional


class NDJSONBufferedWriter:
    """Buffered NDJSON writer with periodic flush and best-effort permissions.

    Usage:
      w = NDJSONBufferedWriter(path, flush_every=20)
      w.write(obj)
      w.flush()  # at end
    """

    def __init__(self, path: Path, flush_every: int = 20, mode: str = "a"):
        self.path = Path(path)
        self.flush_every = max(1, int(flush_every))
        self._buf = []
        self._count = 0
        self._fh = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self._fh = self.path.open(mode, encoding="utf-8")
            # try to set restrictive perms on POSIX
            try:
                os.chmod(self.path, 0o600)
            except Exception:
                pass
        except Exception:
            self._fh = None

    def write(self, obj: Dict[str, Any]) -> None:
        try:
            line = json.dumps(obj, sort_keys=True, ensure_ascii=False)
            if self._fh is None:
                # fallback: try to open lazily
                try:
                    self._fh = self.path.open("a", encoding="utf-8")
                except Exception:
                    return
            self._fh.write(line + "\n")
            self._count += 1
            if (self._count % self.flush_every) == 0:
                try:
                    self._fh.flush()
                except Exception:
                    pass
        except Exception:
            # best-effort: do not raise
            return

    def flush(self) -> None:
        try:
            if self._fh is None:
                return
            try:
                self._fh.flush()
            except Exception:
                pass
            try:
                self._fh.close()
            except Exception:
                pass
            self._fh = None
        except Exception:
            pass


def atomic_write_json(path: Path, obj: Dict[str, Any]) -> None:
    """Write a JSON file atomically via temp suffix and replace.

    Best-effort, avoids partial files on crash.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(obj, f, sort_keys=True, ensure_ascii=False, indent=2)
            try:
                f.flush()
            except Exception:
                pass
        try:
            tmp.replace(path)
        except Exception:
            try:
                tmp.rename(path)
            except Exception:
                # last-resort: write directly
                with path.open("w", encoding="utf-8") as f:
                    json.dump(obj, f, sort_keys=True, ensure_ascii=False, indent=2)
    except Exception:
        pass
