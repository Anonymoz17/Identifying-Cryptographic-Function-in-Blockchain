import json
import pathlib

import pytest


def _load_first_ndjson(path: pathlib.Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            return json.loads(line)
    return None


def test_manifest_and_index_against_schemas(tmp_path, monkeypatch):
    jsonschema = pytest.importorskip("jsonschema")
    from src.auditor.preproc import preprocess_items

    # prepare a small case
    d = tmp_path / "case"
    d.mkdir()
    src = d / "file.txt"
    src.write_text("hello")
    item = {
        "path": str(src),
        "size": src.stat().st_size,
        "mtime": src.stat().st_mtime,
        "sha256": "",
    }

    res = preprocess_items([item], str(d))
    manifest_path = pathlib.Path(res.get("manifest_path"))
    assert manifest_path.exists()

    # load schemas
    schema_dir = pathlib.Path(__file__).resolve().parents[1] / "schemas"
    manifest_schema = json.load(open(schema_dir / "inputs.manifest.schema.json"))
    index_schema = json.load(open(schema_dir / "preproc.index.schema.json"))

    first_manifest = _load_first_ndjson(manifest_path)
    assert first_manifest is not None
    # validate; if sha pattern fails because we produced an empty/invalid sha,
    # we'll get a ValidationError and the test will fail (good signal)
    jsonschema.validate(instance=first_manifest, schema=manifest_schema)

    index_path = pathlib.Path(str(d)) / "preproc.index.jsonl"
    first_index = _load_first_ndjson(index_path)
    assert first_index is not None
    jsonschema.validate(instance=first_index, schema=index_schema)
