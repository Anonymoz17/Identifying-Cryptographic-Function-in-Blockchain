import hashlib
from pathlib import Path

from auditor.preproc import preprocess_items
from src.detectors.adapter import RegexAdapter
from src.detectors.runner import load_manifest_paths


def test_preproc_to_detectors(tmp_path: Path):
    # create a temporary case workdir and a small input file
    wd = tmp_path / "case"
    wd.mkdir()
    src = wd / "input.txt"
    src.write_text("const SECRET_KEY = 'abcd';\nfunction foo() {}\n", encoding="utf-8")

    # compute sha and prepare manifest-like item (preproc will accept it)
    sha = hashlib.sha256(src.read_bytes()).hexdigest()
    item = {
        "path": str(src),
        "size": src.stat().st_size,
        "mtime": src.stat().st_mtime,
        "sha256": sha,
    }

    # run preprocessing (we don't need the returned object for this test)
    preprocess_items([item], str(wd))

    # ensure manifest was written
    manifest = wd / "inputs.manifest.ndjson"
    assert manifest.exists(), "inputs.manifest.ndjson was not created"

    # load file paths the detectors will scan
    files = load_manifest_paths(str(manifest))
    assert files, "load_manifest_paths returned no files"

    # expected canonical copy under preproc/<sha>/input.bin
    expected = wd / "preproc" / sha / "input.bin"
    # ensure the expected file is among the returned paths (resolve for safety)
    assert any(
        Path(f).resolve() == expected.resolve() for f in files
    ), f"expected {expected} in files: {files}"

    # run a simple regex adapter on the returned files
    adapter = RegexAdapter({"secret": r"SECRET_KEY"})
    found = list(adapter.scan_files(files))
    assert any(
        d.rule == "secret" for d in found
    ), "RegexAdapter did not find SECRET_KEY"
