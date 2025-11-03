from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Callable, Optional

from .persistence import atomic_write_json


@dataclass
class ProgressUpdate:
    phase: str
    processed: int
    total: Optional[int]
    percent: Optional[float]
    speed: float
    elapsed_s: float
    eta_s: Optional[int]
    status: str


class ProgressReporter:
    """Thread-safe progress reporter that throttles UI callbacks and writes a summary.

    Usage: create with ui_callback that accepts ProgressUpdate. Call
    start_phase(), update_total(), tick() or update_processed(), set_phase_status(),
    and finish_phase(). A small JSON summary is written to file_path if provided.
    """

    def __init__(self, *, ui_callback: Optional[Callable[[ProgressUpdate], None]] = None, file_path: Optional[Path] = None, throttle_s: float = 0.2):
        self.ui_callback = ui_callback
        self.file_path = Path(file_path) if file_path else None
        self.throttle_s = float(throttle_s)

        self._lock = threading.Lock()
        self._phase = "idle"
        self._status = ""
        self._processed = 0
        self._total = None
        self._start = None
        self._last_emit = 0.0
        self._speed = 0.0
        self._last_count = 0
        self._last_time = None

    def start_phase(self, name: str, total: Optional[int] = None) -> None:
        with self._lock:
            self._phase = name
            self._status = ""
            self._processed = 0
            self._total = int(total) if total is not None else None
            self._start = time.monotonic()
            self._last_emit = 0.0
            self._speed = 0.0
            self._last_count = 0
            self._last_time = self._start
        self._maybe_emit()

    def update_total(self, total: int) -> None:
        with self._lock:
            self._total = int(total)
        self._maybe_emit()

    def set_phase_status(self, text: str) -> None:
        with self._lock:
            self._status = text
        self._maybe_emit()

    def tick(self, n: int = 1) -> None:
        with self._lock:
            self._processed += int(n)
            now = time.monotonic()
            elapsed = now - (self._last_time or now)
            if elapsed > 0:
                inst_rate = (self._processed - self._last_count) / elapsed
                # exponential smoothing
                alpha = 0.2
                self._speed = alpha * inst_rate + (1 - alpha) * self._speed
                self._last_count = self._processed
                self._last_time = now
        self._maybe_emit()

    def update_processed(self, processed: int) -> None:
        with self._lock:
            prev = self._processed
            self._processed = int(processed)
            now = time.monotonic()
            elapsed = now - (self._last_time or now)
            if elapsed > 0:
                inst_rate = (self._processed - prev) / elapsed
                alpha = 0.2
                self._speed = alpha * inst_rate + (1 - alpha) * self._speed
                self._last_count = self._processed
                self._last_time = now
        self._maybe_emit()

    def snapshot(self) -> ProgressUpdate:
        with self._lock:
            elapsed = (time.monotonic() - (self._start or time.monotonic()))
            percent = None
            eta = None
            if self._total and self._total > 0:
                percent = min(1.0, float(self._processed) / float(self._total))
                if self._speed > 1e-6:
                    remain = max(0, int((self._total - self._processed) / self._speed))
                    eta = remain
            pu = ProgressUpdate(
                phase=self._phase,
                processed=self._processed,
                total=self._total,
                percent=percent,
                speed=self._speed,
                elapsed_s=int(elapsed),
                eta_s=eta,
                status=self._status,
            )
        return pu

    def _maybe_emit(self) -> None:
        now = time.monotonic()
        if now - self._last_emit < self.throttle_s:
            return
        self._last_emit = now
        pu = self.snapshot()
        # UI callback
        if self.ui_callback:
            try:
                self.ui_callback(pu)
            except Exception:
                pass
        # persist small JSON summary
        if self.file_path:
            try:
                self.file_path.parent.mkdir(parents=True, exist_ok=True)
                atomic_write_json(self.file_path, asdict(pu))
            except Exception:
                pass

    def finish_phase(self) -> None:
        # final emit
        self._maybe_emit()

    def close(self) -> None:
        try:
            self.finish_phase()
        except Exception:
            pass
