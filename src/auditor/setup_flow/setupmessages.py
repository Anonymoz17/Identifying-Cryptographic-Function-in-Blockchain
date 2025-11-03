from __future__ import annotations

import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Optional


@dataclass
class Message:
    level: str
    text: str
    path: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    # Use timezone-aware UTC timestamp to avoid deprecation of utcnow()
    ts: str = datetime.now(timezone.utc).isoformat()

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)


class Notifier:
    """Simple notifier that can write messages to console, file or call a UI callback.

    Handlers:
    - console: prints human-readable bracketed messages
    - file: append NDJSON (one JSON object per line)
    - ui_callback: callable(Message) used by UI code to present expandable entries
    """

    def __init__(self, *, file_path: Optional[str] = None, ui_callback: Optional[Callable[[Message], None]] = None):
        self.file_path = file_path
        self.ui_callback = ui_callback

    def emit(self, msg: Message) -> None:
        # Console output
        label = f"[{msg.level}]"
        if msg.path:
            print(f"{label} {msg.path} - {msg.text}")
        else:
            print(f"{label} {msg.text}")

        # File output (NDJSON)
        if self.file_path:
            try:
                with open(self.file_path, "a", encoding="utf-8") as fh:
                    fh.write(msg.to_json() + "\n")
            except Exception:
                # avoid raising from logging
                pass

        # UI callback
        if self.ui_callback:
            try:
                self.ui_callback(msg)
            except Exception:
                pass

    # convenience helpers
    def info(self, text: str, path: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
        self.emit(Message(level="INFO", text=text, path=path, details=details))

    def ok(self, text: str, path: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
        self.emit(Message(level="OK", text=text, path=path, details=details))

    def skip(self, text: str, path: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
        self.emit(Message(level="SKIP", text=text, path=path, details=details))

    def warn(self, text: str, path: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> None:
        self.emit(Message(level="WARN", text=text, path=path, details=details))
