import json
from pathlib import Path

from src.auditor import preproc


def _write_minimal_aarch64_elf(path: Path):
    hdr = bytearray(b"\x7fELF")
    hdr += bytes([2, 1, 1, 0])
    hdr += bytes(8)
    hdr += (0).to_bytes(2, "little")
    # e_machine = 183 for aarch64
    hdr += (183).to_bytes(2, "little")
    hdr += (1).to_bytes(4, "little")
    path.write_bytes(bytes(hdr))


def test_disasm_aarch64_creates_artifact(tmp_path: Path):
    wd = tmp_path
    preproc_dir = wd / "preproc"
    preproc_dir.mkdir(parents=True, exist_ok=True)
    sha = "c" * 64
    item_dir = preproc_dir / sha
    item_dir.mkdir(parents=True, exist_ok=True)
    # write input.bin with minimal ELF header and some bytes
    binp = item_dir / "input.bin"
    _write_minimal_aarch64_elf(binp)
    binp.write_bytes(binp.read_bytes() + b"\x00\x00\x00\x00")

    preproc.build_disasm_cache([sha], str(wd))

    out = wd / "artifacts" / "disasm" / (sha + ".json")
    assert out.exists()
    obj = json.loads(out.read_text(encoding="utf-8"))
    assert obj.get("sha") == sha
    assert "disasm" in obj
