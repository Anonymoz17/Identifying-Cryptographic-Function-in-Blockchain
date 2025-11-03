import json
import time
from pathlib import Path

import pytest

from src.auditor.setup_flow.progress import ProgressReporter


class TimeMock:
    def __init__(self, start: float = 1000.0):
        self.t = start

    def advance(self, dt: float) -> None:
        self.t += dt

    def monotonic(self) -> float:
        return self.t


def test_progress_basic_and_eta(tmp_path, monkeypatch):
    tm = TimeMock()
    monkeypatch.setattr(time, "monotonic", tm.monotonic)

    calls = []
    out_file = tmp_path / "progress.json"
    reporter = ProgressReporter(ui_callback=lambda pu: calls.append(pu), file_path=out_file, throttle_s=0.0)

    # start with total 10
    reporter.start_phase("preprocessing", total=10)

    # advance 1s and process 5 items
    tm.advance(1.0)
    reporter.tick(5)

    # snapshot should reflect 5/10, speed ~1.0 (see smoothing in implementation)
    pu = reporter.snapshot()
    assert pytest.approx(0.5, rel=1e-6) == pu.percent
    # first smoothed speed should be close to 1.0 (alpha * inst_rate where inst_rate=5.0)
    assert pu.speed > 0.9 and pu.speed < 1.1
    assert pu.eta_s == 5

    # progress.json should have been written and contain matching phase
    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data.get("phase") == "preprocessing"


def test_throttling_behavior(monkeypatch):
    tm = TimeMock()
    monkeypatch.setattr(time, "monotonic", tm.monotonic)

    calls = []
    reporter = ProgressReporter(ui_callback=lambda pu: calls.append(pu), throttle_s=0.5, file_path=None)
    reporter.start_phase("phase", total=10)

    # advance slightly, tick once: should NOT emit because within throttle window from start_phase
    tm.advance(0.1)
    reporter.tick(1)
    assert len(calls) == 1

    # advance beyond throttle, tick again: should emit a second time
    tm.advance(0.6)
    reporter.tick(1)
    assert len(calls) >= 2
