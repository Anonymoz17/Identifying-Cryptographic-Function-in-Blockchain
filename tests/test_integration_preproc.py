import json
from pathlib import Path

from auditor.preproc import preprocess_items


def test_preprocess_creates_artifacts(tmp_path: Path):
    # create a small input file and a manifest-like item
    d = tmp_path / "case"
    d.mkdir()
    src = d / "input.bin"
    src.write_bytes(b"hello-world")

    item = {
        "path": str(src),
        "size": src.stat().st_size,
        "mtime": src.stat().st_mtime,
        "sha256": "dummysha1234567890",
    }

    idx = preprocess_items([item], str(d))
    # expect an index entry and a preproc dir
    assert isinstance(idx, list)
    assert len(idx) == 1
    preproc_dir = d / "preproc" / item["sha256"]
    assert preproc_dir.exists()
    assert (preproc_dir / "metadata.json").exists()
    # index file
    index_path = d / "preproc.index.jsonl"
    assert index_path.exists()
    lines = [
        json.loads(line)
        for line in index_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert len(lines) == 1
    assert lines[0]["sha256"] == item["sha256"]
