import json
from pathlib import Path

from src.auditor import preproc


def test_build_disasm_cache_creates_file(tmp_path: Path):
    workdir = tmp_path
    preproc_dir = workdir / "preproc"
    preproc_dir.mkdir(parents=True, exist_ok=True)
    sha = "b" * 64
    item_dir = preproc_dir / sha
    item_dir.mkdir(parents=True, exist_ok=True)
    # write a small x86-64 nop sled (valid bytes to disassemble if capstone available)
    item_dir.joinpath("input.bin").write_bytes(b"\x90\x90\x90\x90\xc3")

    preproc.build_disasm_cache([sha], str(workdir))

    out = workdir / "artifacts" / "disasm" / (sha + ".json")
    assert out.exists(), "Disasm cache file not created"
    obj = json.loads(out.read_text(encoding="utf-8"))
    assert obj.get("sha") == sha
    # disasm may be None when capstone is absent; that's acceptable
    assert "disasm" in obj
