import json
import subprocess

import pytest

from src.detectors.semgrep_adapter import SemgrepCliAdapter


def fake_semgrep_output_dict():
    return json.dumps(
        {
            "results": [
                {
                    "path": "preproc/fakesha/input.bin",
                    "check_id": "S1",
                    "start": {"line": 10},
                    "extra": {"message": "matched", "lines": ["foo()", "bar()"]},
                }
            ]
        }
    ).encode("utf-8")


def fake_semgrep_output_list():
    return json.dumps(
        [
            {
                "path": "preproc/fakesha/input.bin",
                "rule_id": "R1",
                "location": {"start": {"line": 20}},
                "extra": {"message": "m2"},
            }
        ]
    ).encode("utf-8")


@pytest.mark.parametrize(
    "out_bytes", [fake_semgrep_output_dict(), fake_semgrep_output_list()]
)
def test_semgrep_adapter_parses(monkeypatch, tmp_path, out_bytes):
    # monkeypatch subprocess.check_output to return our fake output
    def fake_check_output(cmd, stderr=None):
        return out_bytes

    monkeypatch.setattr(subprocess, "check_output", fake_check_output)
    # pretend semgrep exists on PATH
    import shutil

    monkeypatch.setattr(shutil, "which", lambda name: "semgrep")

    adapter = SemgrepCliAdapter(rules_dir=None, fallback_rules={})
    dets = list(adapter.scan_files([str(tmp_path / "dummy")]))
    assert len(dets) == 1
    d = dets[0]
    assert d.engine == "semgrep"
    assert d.rule in ("S1", "R1", "semgrep")
    assert d.details and "snippet" in d.details
