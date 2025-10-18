import json
import zipfile
from pathlib import Path

from src.auditor.preproc import preprocess_items


def test_extract_and_manifest(tmp_path: Path):
    d = tmp_path / "case"
    d.mkdir()
    # create a small zip archive with one file
    archive = d / "sample.zip"
    with zipfile.ZipFile(str(archive), "w") as zf:
        zf.writestr("inner.txt", "hello-extracted")

    item = {
        "path": str(archive),
        "size": archive.stat().st_size,
        "mtime": archive.stat().st_mtime,
        "sha256": "zipsha",
    }

    preprocess_items([item], str(d))
    # manifest should be written
    manifest = d / "inputs.manifest.ndjson"
    assert manifest.exists()
    lines = [
        json.loads(line)
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    # expect at least one entry (for the archive) and extracted entry
    assert any(entry.get("origin", "").startswith("extracted:") for entry in lines)
