import json
from pathlib import Path

from src.auditor.preproc import preprocess_items


def test_missing_source_reports_error(tmp_path: Path):
    d = tmp_path / "case"
    d.mkdir()
    # create an item referencing a non-existent file
    item = {
        "path": str(d / "nope.bin"),
        "size": 0,
        "mtime": None,
        "sha256": "missingsha",
    }
    preprocess_items([item], str(d))
    manifest = d / "inputs.manifest.ndjson"
    assert manifest.exists()
    lines = [
        json.loads(line)
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(
        entry.get("extra", {}).get("error") == "source_missing" for entry in lines
    )
