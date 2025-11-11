import json
import os
from src.auditor.detectors.static_detection.results_packager import package_results


def test_package_results_writes_files(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    file_hash = "a" * 64
    findings = []
    meta = {"profile": "quick", "tool_versions": {}}
    path = package_results(file_hash, findings, str(out), meta=meta)
    assert os.path.isfile(path)
    payload = json.loads(open(path, "r", encoding="utf-8").read())
    assert payload.get("schema_version") == "1.0"
    cache_meta_path = os.path.join(str(out), ".cache_meta.json")
    assert os.path.isfile(cache_meta_path)
    cache_meta = json.loads(open(cache_meta_path, "r", encoding="utf-8").read())
    assert cache_meta.get("file_hash") == file_hash
