import json
from pathlib import Path

from src.detectors.adapter import RegexAdapter
from src.detectors.merge import dedupe_detections
from src.detectors.runner import (
    load_manifest_paths,
    run_adapters,
    write_ndjson_detections,
)


def test_runner_and_merge(tmp_path: Path):
    d = tmp_path
    # create a fake manifest with two entries pointing to files we will create
    f1 = d / "a.sol"
    f1.write_text("function secret() {}\nfunction secret() {}", encoding="utf-8")
    manifest = d / "inputs.manifest.ndjson"
    manifest.write_text(json.dumps({"path": str(f1)}) + "\n")

    paths = load_manifest_paths(str(manifest))
    assert str(f1) in paths

    adapter = RegexAdapter({"func": r"function\s+([A-Za-z0-9_]+)"})
    dets = list(run_adapters([adapter], paths))
    # we should see two detections (two matching functions)
    assert len(dets) >= 2

    # dedupe should collapse duplicates by (path, offset, rule); use sample where offsets differ
    dd = dedupe_detections(dets)
    assert isinstance(dd, list)

    out = d / "detector_results.ndjson"
    write_ndjson_detections(dd, str(out))
    assert out.exists()
    lines = [
        json.loads(line)
        for line in out.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) == len(dd)
