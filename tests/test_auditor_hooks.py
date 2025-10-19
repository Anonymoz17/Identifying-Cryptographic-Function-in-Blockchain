from pathlib import Path

from src.auditor.preproc import build_ast_cache, build_disasm_cache


def test_build_ast_and_disasm_create_files(tmp_path: Path):
    wd = tmp_path / "case"
    wd.mkdir()
    shas = ["deadbeef", "cafecafe"]
    build_ast_cache(shas, str(wd))
    build_disasm_cache(shas, str(wd))

    for s in shas:
        astf = wd / "artifacts" / "ast" / (s + ".json")
        disf = wd / "artifacts" / "disasm" / (s + ".json")
        assert astf.exists()
        assert disf.exists()
        # ensure files contain the sha
        assert s in astf.read_text(encoding="utf-8")
        assert s in disf.read_text(encoding="utf-8")
