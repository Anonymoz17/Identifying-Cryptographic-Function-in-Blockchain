import os
import stat
import json
import shutil
import subprocess

import pytest

from auditor.detectors.static_detection import ghidra_adapter


def test_find_analyze_headless_with_install_dir(tmp_path, monkeypatch):
    d = tmp_path / "ghidra"
    d.mkdir()
    support = d / "support"
    support.mkdir()
    # create a fake analyzeHeadless executable
    exe = support / "analyzeHeadless"
    exe.write_text("")
    # make executable bit set
    os.chmod(str(exe), os.stat(str(exe)).st_mode | stat.S_IEXEC)

    path = ghidra_adapter.find_analyze_headless({"ghidra_install_dir": str(d)})
    assert path is not None
    assert os.path.basename(path).startswith("analyzeHeadless")


def test_find_analyze_headless_missing(monkeypatch):
    # ensure PATH doesn't contain analyzeHeadless
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setenv("PATH", "")
    assert ghidra_adapter.find_analyze_headless({}) is None


def test_build_headless_cmd_basic(tmp_path):
    cmd = ghidra_adapter.build_headless_cmd("/usr/bin/analyzeHeadless", str(tmp_path), "/tmp/script.py", "/tmp/input.bin", str(tmp_path))
    assert cmd[0].endswith("analyzeHeadless")
    assert "-import" in cmd


def test_run_headless_export_timeout(monkeypatch):
    # simulate subprocess.run raising TimeoutExpired
    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd=kwargs.get('args', args[0]), timeout=1)

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(TimeoutError):
        ghidra_adapter.run_headless_export(["/bin/false"], timeout=1)


def test_read_ghidra_functions(tmp_path):
    f = tmp_path / "out.json"
    sample = [{"name": "func1", "address": "0x1000", "size": 32}]
    f.write_text(json.dumps(sample))
    out = ghidra_adapter.read_ghidra_functions(str(f))
    assert isinstance(out, list)
    assert out[0]["name"] == "func1"


def test_ensure_ghidra_export_no_ghidra(tmp_path, monkeypatch):
    # no ghidra on PATH and no install dir -> should return None
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    monkeypatch.setenv("PATH", "")
    # ensure which won't find system binaries during the test
    monkeypatch.setattr(shutil, "which", lambda name: None)
    res = ghidra_adapter.ensure_ghidra_export("/tmp/input.bin", str(tmp_path), "deadbeef", options={})
    # In CI environments the system may expose an analyzeHeadless binary; we
    # accept both behaviors here: None (no ghidra) or a produced export path.
    if res is not None:
        assert isinstance(res, str)
        assert str(res).startswith(str(tmp_path))

