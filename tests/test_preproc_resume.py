import hashlib
import json
from pathlib import Path

from auditor.preproc import preprocess_items


def write_index_line(path: Path, idx: dict):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(idx, sort_keys=True, ensure_ascii=False) + "\n")


def test_preproc_resume(tmp_path):
    # prepare workdir and an existing preproc entry for sha1
    workdir = tmp_path
    sha1 = "a" * 64

    preproc_dir = workdir / "preproc"
    preproc_dir.mkdir(parents=True, exist_ok=True)
    # create artifact dir for sha1 to simulate prior work
    (preproc_dir / sha1).mkdir(parents=True, exist_ok=True)
    (preproc_dir / sha1 / "metadata.json").write_text(json.dumps({"id": sha1}))

    index_path = workdir / "preproc.index.jsonl"
    # write an index line for sha1
    write_index_line(index_path, {"manifest_id": sha1, "sha256": sha1})

    # create a small file for sha2 to be processed
    src2 = workdir / "file2.bin"
    src2.write_bytes(b"hello world")
    # compute sha2
    h = hashlib.sha256()
    h.update(src2.read_bytes())
    sha2_computed = h.hexdigest()

    items = [
        {"path": str(workdir / "missing.bin"), "sha256": sha1},  # should be skipped
        {"path": str(src2), "sha256": sha2_computed},
    ]

    # run preprocess in streaming + resume mode
    res = preprocess_items(items, str(workdir), stream=True, resume=True)

    # stats should indicate processed == 2
    assert res["stats"]["processed"] == 2

    # index file should contain an entry for the new sha (sha2_computed)
    idx_lines = [
        json.loads(line)
        for line in index_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    ids = {line.get("manifest_id") for line in idx_lines}
    assert sha1 in ids
    assert sha2_computed in ids

    # manifest file should exist and include the new sha entry
    manifest_path = workdir / "inputs.manifest.ndjson"
    assert manifest_path.exists()
    man_lines = [
        json.loads(line)
        for line in manifest_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    man_ids = {m.get("id") for m in man_lines}
    assert sha2_computed in man_ids
