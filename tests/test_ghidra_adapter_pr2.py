import json
import json
import os
import pytest

from src.auditor.detectors.static_detection import ghidra_adapter as ga


def _sample_functions():
    return [
        {"name": "func_a", "address": "0x1000", "size": 64, "prototype": "int f()", "disasm": "..."},
    ]


def test_ensure_ghidra_export_with_mocked_run(tmp_path, monkeypatch):
    inp = tmp_path / "input.bin"
    inp.write_bytes(b"deadbeef")
    out_dir = tmp_path / "out"
    fh = "abcd1234"

    # monkeypatch find_analyze_headless to return a fake path
    monkeypatch.setattr(ga, "find_analyze_headless", lambda opts=None: "/fake/analyze")

    # monkeypatch run_headless_export to simulate writing the export file
    def fake_run(cmd, timeout=600):
        os.makedirs(out_dir, exist_ok=True)
        export_path = out_dir / f"{fh}-functions.json"
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump(_sample_functions(), f)
        return 0, "ok", ""

    monkeypatch.setattr(ga, "run_headless_export", fake_run)

    # Call ensure_ghidra_export
    result = ga.ensure_ghidra_export(str(inp), str(out_dir), fh, options={})
    assert result is not None
    assert os.path.isfile(result)

    funcs = ga.read_ghidra_functions(result)
    assert isinstance(funcs, list)
    assert funcs and funcs[0]["name"] == "func_a"


def test_ensure_ghidra_export_force_rerun_overwrites(tmp_path, monkeypatch):
    inp = tmp_path / "input.bin"
    inp.write_bytes(b"cafebabe")
    out_dir = tmp_path / "out2"
    fh = "beef5678"
    os.makedirs(out_dir, exist_ok=True)
    existing = out_dir / f"{fh}-functions.json"
    # write initial content
    with open(existing, "w", encoding="utf-8") as f:
        json.dump([{"name": "old"}], f)

    # ensure find_analyze_headless returns something
    monkeypatch.setattr(ga, "find_analyze_headless", lambda opts=None: "/fake/analyze")

    # fake run will overwrite file
    def fake_run2(cmd, timeout=600):
        export_path = out_dir / f"{fh}-functions.json"
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump([{"name": "new"}], f)
        return 0, "ok", ""

    monkeypatch.setattr(ga, "run_headless_export", fake_run2)

    # force rerun
    result = ga.ensure_ghidra_export(str(inp), str(out_dir), fh, options={"force": True})
    assert result is not None
    funcs = ga.read_ghidra_functions(result)
    assert funcs[0]["name"] == "new"


def test_ensure_ghidra_export_no_analyze(tmp_path, monkeypatch):
    inp = tmp_path / "input.bin"
    inp.write_bytes(b"00")
    out_dir = tmp_path / "out3"
    fh = "nope"

    # No analyze available
    monkeypatch.setattr(ga, "find_analyze_headless", lambda opts=None: None)

    # Ensure no export exists
    res = ga.ensure_ghidra_export(str(inp), str(out_dir), fh, options={})
    assert res is None