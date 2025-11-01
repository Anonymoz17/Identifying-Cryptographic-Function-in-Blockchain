import json
from pathlib import Path

from auditor.intake import enumerate_inputs


def write_file(p: Path, size: int = 10):
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "wb") as f:
        f.write(b"x" * size)


def test_enumerate_include_exclude_and_size(tmp_path: Path):
    # create files of different names and sizes
    a = tmp_path / "a.sol"
    b = tmp_path / "b.py"
    src_dir = tmp_path / "src"
    c = src_dir / "c.sol"
    node = tmp_path / "node_modules" / "pkg.js"
    large = tmp_path / "big.bin"

    write_file(a, size=50)
    write_file(b, size=20)
    write_file(c, size=30)
    write_file(node, size=10)
    write_file(large, size=5000)

    # include only .sol files
    items = enumerate_inputs(
        [str(tmp_path)],
        include_globs=["*.sol"],
        exclude_globs=None,
        max_file_size_bytes=None,
    )
    paths = {Path(i["path"]).name for i in items}
    assert "a.sol" in paths
    assert "c.sol" in paths
    assert "b.py" not in paths

    # exclude node_modules
    items2 = enumerate_inputs(
        [str(tmp_path)],
        include_globs=None,
        exclude_globs=["node_modules/*"],
        max_file_size_bytes=None,
    )
    names2 = {Path(i["path"]).name for i in items2}
    assert "pkg.js" not in names2

    # apply max size (skip big.bin)
    items3 = enumerate_inputs(
        [str(tmp_path)],
        include_globs=None,
        exclude_globs=None,
        max_file_size_bytes=1024,
    )
    names3 = {Path(i["path"]).name for i in items3}
    assert "big.bin" not in names3


def test_cli_invocation_writes_manifest(tmp_path: Path, monkeypatch):
    # monkeypatch preprocess_items to avoid heavy work
    from auditor import cli

    def fake_preproc(items, root, **kwargs):
        return {"stats": {"index_lines": 0}}

    monkeypatch.setattr("auditor.preproc.preprocess_items", fake_preproc)

    workdir = tmp_path / "work"
    scope = tmp_path / "scope"
    scope.mkdir()
    (scope / "ok.sol").write_text("contract {}")

    argv = [
        "--workdir",
        str(workdir),
        "--case-id",
        "CASE-CLI",
        "--scope",
        str(scope),
        "--include",
        "*.sol",
        "--max-size-kb",
        "1",
    ]

    # run CLI main
    cli.main(argv)

    # verify manifest exists and contains 1 item
    ws_root = Path(workdir).resolve() / "CASE-CLI"
    manifest = ws_root / "inputs.manifest.json"
    assert manifest.exists()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert isinstance(data.get("items"), list)
    # should include ok.sol (small) and count == 1
    assert len(data["items"]) == 1
