import json
from pathlib import Path

from auditor.preproc import preprocess_items


def test_preprocess_accepts_numeric_mtime(tmp_path: Path):
    d = tmp_path / "case"
    d.mkdir()
    src = d / "input.bin"
    src.write_bytes(b"hello-world")

    item = {
        "path": str(src),
        "size": src.stat().st_size,
        # pass numeric mtime (float)
        "mtime": src.stat().st_mtime,
        "sha256": "dummysha_numeric",
    }

    res = preprocess_items([item], str(d))
    idx = res.get("index", [])
    assert len(idx) == 1
    meta_path = d / "preproc" / item["sha256"] / "metadata.json"
    assert meta_path.exists()
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    # mtime in metadata should be a string (ISO) when normalization succeeds
    assert isinstance(meta.get("mtime"), str)
