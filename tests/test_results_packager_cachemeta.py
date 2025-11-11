import json
import os
from datetime import datetime, timezone

from auditor.detectors.static_detection import results_packager


def test_package_writes_cache_meta(tmp_path):
    out = tmp_path / "analysis"
    out.mkdir()
    file_hash = "beefcafe"
    findings = [{"id": "f1", "score": 0.9}]
    meta = {"profile": "quick", "tool_versions": {"ghidra": "9.2"}, "ghidra_export": "/tmp/ghidra.json"}

    path = results_packager.package_results(file_hash, findings, str(out), meta=meta)
    assert os.path.isfile(path)

    cache_meta_path = out / ".cache_meta.json"
    assert cache_meta_path.exists()
    cache_meta = json.loads(cache_meta_path.read_text(encoding="utf-8"))
    assert cache_meta.get("file_hash") == file_hash
    assert cache_meta.get("profile") == "quick"
    assert cache_meta.get("ghidra_export") == "/tmp/ghidra.json"
    # timestamp should be parseable ISO timestamp
    ts = cache_meta.get("generated_at")
    assert ts is not None
    # quick sanity parse
    datetime.fromisoformat(ts)
