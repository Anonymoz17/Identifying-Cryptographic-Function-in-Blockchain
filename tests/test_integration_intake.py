import json
from pathlib import Path

from auditor.intake import enumerate_inputs, write_manifest


def test_enumerate_and_write_manifest(tmp_path: Path):
    # create two small files
    d = tmp_path / "sample"
    d.mkdir()
    f1 = d / "a.txt"
    f1.write_text("hello")
    f2 = d / "b.bin"
    f2.write_bytes(b"\x00\x01\x02")

    items = enumerate_inputs([str(d)])
    assert isinstance(items, list)
    assert len(items) >= 2

    for it in items:
        assert "path" in it and "sha256" in it and "size" in it and "mtime" in it

    manifest_path = tmp_path / "inputs.manifest.json"
    write_manifest(str(manifest_path), items)
    assert manifest_path.exists()
    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert "generated_at" in data and isinstance(data.get("items"), list)
    assert len(data["items"]) == len(items)
