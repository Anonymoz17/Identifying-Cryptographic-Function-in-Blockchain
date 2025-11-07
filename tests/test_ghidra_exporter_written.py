import os
import json

from src.auditor.detectors.static_detection import ghidra_adapter as ga


def test_bundled_exporter_written_and_used(tmp_path, monkeypatch):
    inp = tmp_path / "input.bin"
    inp.write_bytes(b"abc")
    out_dir = tmp_path / "out"
    fh = "feedface"

    # ensure find_analyze_headless returns something (so adapter attempts to run)
    monkeypatch.setattr(ga, "find_analyze_headless", lambda opts=None: "/fake/analyze")

    # monkeypatch run_headless_export to create expected export and assert script exists
    def fake_run(cmd, timeout=600):
        # cmd should include -postScript and -scriptPath when using bundled script
        joined = " ".join(cmd)
        assert "-postScript" in joined or "-scriptPath" in joined
        # ensure the bundled script was written to out_dir
        script_path = os.path.join(str(out_dir), "ghidra_exporter.py")
        assert os.path.isfile(script_path)
        # write the export file as Ghidra would
        export_path = os.path.join(str(out_dir), f"{fh}-functions.json")
        with open(export_path, "w", encoding="utf-8") as f:
            json.dump([{"name": "bfunc"}], f)
        return 0, "ok", ""

    monkeypatch.setattr(ga, "run_headless_export", fake_run)

    res = ga.ensure_ghidra_export(str(inp), str(out_dir), fh, options={})
    assert res is not None
    assert os.path.isfile(os.path.join(str(out_dir), "ghidra_exporter.py"))
    funcs = ga.read_ghidra_functions(res)
    assert funcs and funcs[0]["name"] == "bfunc"
