from pathlib import Path
import json

from auditor.setup_flow import persistence


def test_ndjson_buffered_writer(tmp_path):
    p = tmp_path / "out.ndjson"
    w = persistence.NDJSONBufferedWriter(p, flush_every=1)
    w.write({"a": 1})
    w.write({"b": 2})
    w.flush()

    text = p.read_text(encoding="utf-8")
    lines = [json.loads(l) for l in text.strip().splitlines() if l.strip()]
    assert {"a": 1} in lines
    assert {"b": 2} in lines


def test_atomic_write_json(tmp_path):
    p = tmp_path / "summary.json"
    obj = {"x": 1}
    persistence.atomic_write_json(p, obj)
    assert p.exists()
    loaded = json.loads(p.read_text(encoding="utf-8"))
    assert loaded == obj
