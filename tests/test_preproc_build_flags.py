import json
from pathlib import Path

from src.auditor.preproc import preprocess_items


def test_preproc_build_flags_calls(tmp_path: Path, monkeypatch):
    # create a fake input file
    inp = tmp_path / "file.txt"
    inp.write_text("hello world")
    import hashlib

    h = hashlib.sha256()
    h.update(inp.read_bytes())
    sha = h.hexdigest()

    item = {"path": str(inp), "sha256": sha, "size": inp.stat().st_size}

    called = {"ast": False, "disasm": False}

    def fake_build_ast(shas, workdir):
        called["ast"] = True
        # write placeholder file
        p = Path(workdir) / "artifacts" / "ast" / (shas[0] + ".json")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"sha": shas[0], "ast": []}))

    def fake_build_disasm(shas, workdir):
        called["disasm"] = True
        p = Path(workdir) / "artifacts" / "disasm" / (shas[0] + ".json")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"sha": shas[0], "disasm": []}))

    monkeypatch.setattr("src.auditor.preproc.build_ast_cache", fake_build_ast)
    monkeypatch.setattr("src.auditor.preproc.build_disasm_cache", fake_build_disasm)

    _ = preprocess_items(
        [item], str(tmp_path), do_extract=False, build_ast=True, build_disasm=True
    )

    # ensure the placeholder artifacts were created and fakes were called
    assert called["ast"]
    assert called["disasm"]
    assert (tmp_path / "artifacts" / "ast" / (sha + ".json")).exists()
    assert (tmp_path / "artifacts" / "disasm" / (sha + ".json")).exists()
