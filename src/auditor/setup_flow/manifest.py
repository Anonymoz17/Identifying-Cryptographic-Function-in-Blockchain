from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from .persistence import NDJSONBufferedWriter, atomic_write_json
from .setupmessages import Notifier


class ManifestWriter(NDJSONBufferedWriter):
    """Convenience wrapper for writing streaming manifests with notifier

    Extends NDJSONBufferedWriter and provides a small helper to write a
    final summary atomically. Also emits notifier messages when writing.
    """

    def __init__(self, path: Path, flush_every: int = 20, notifier: Optional[Notifier] = None):
        super().__init__(Path(path), flush_every=flush_every, mode="a")
        self.notifier = notifier

    def write(self, obj: Dict[str, Any]) -> None:
        super().write(obj)
        if self.notifier:
            try:
                # lightweight info-level notification for UI
                self.notifier.info("manifest: wrote entry", path=obj.get("path"), details={"id": obj.get("id")})
            except Exception:
                pass

    def write_summary(self, summary_path: Path, summary_obj: Dict[str, Any]) -> None:
        try:
            atomic_write_json(Path(summary_path), summary_obj)
            if self.notifier:
                try:
                    self.notifier.info("manifest: wrote summary", path=str(summary_path), details=summary_obj)
                except Exception:
                    pass
        except Exception:
            # best-effort
            pass
