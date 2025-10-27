import json
from pathlib import Path

from src.auditor.preproc import preprocess_items


def _write_minimal_elf(path: Path):
    # ELF header: 0x7fELF + EI_CLASS=2 (64-bit) + EI_DATA=1 (little)
    hdr = bytearray(b"\x7fELF")
    hdr += bytes(
        [2, 1, 1, 0]
    )  # EI_CLASS=2 (64-bit), EI_DATA=1 (LE), EI_VERSION, EI_OSABI
    hdr += bytes(8)  # padding to 16
    # e_type, e_machine, e_version, begin of rest -> set e_machine to 62 (x86_64)
    hdr += (0).to_bytes(2, "little")
    hdr += (62).to_bytes(2, "little")
    hdr += (1).to_bytes(4, "little")
    path.write_bytes(bytes(hdr))


def _write_minimal_pe(path: Path):
    # MZ header, write e_lfanew at offset 0x3c pointing to 0x80
    data = bytearray(b"MZ")
    data += bytes(58)
    data += (0x80).to_bytes(4, "little")
    # pad to 0x80
    if len(data) < 0x80:
        data += bytes(0x80 - len(data))
    # write PE signature and Machine (0x8664 -> x86_64)
    data += b"PE\x00\x00"
    data += (0x8664).to_bytes(2, "little")
    path.write_bytes(bytes(data))


def _write_minimal_wasm(path: Path):
    # WASM magic
    path.write_bytes(b"\x00asm" + b"\x01\x00\x00\x00")


def test_binary_metadata_elf(tmp_path: Path):
    d = tmp_path / "case"
    d.mkdir()
    f = d / "a.elf"
    _write_minimal_elf(f)
    it = {
        "path": str(f),
        "size": f.stat().st_size,
        "mtime": f.stat().st_mtime,
        "sha256": "elfsha",
    }
    preprocess_items([it], str(d))
    manifest = d / "inputs.manifest.ndjson"
    assert manifest.exists()
    lines = [
        json.loads(line)
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(
        rec.get("binary_format") == "elf" and rec.get("arch") == "x86_64"
        for rec in lines
    )


def test_binary_metadata_pe(tmp_path: Path):
    d = tmp_path / "case"
    d.mkdir()
    f = d / "a.exe"
    _write_minimal_pe(f)
    it = {
        "path": str(f),
        "size": f.stat().st_size,
        "mtime": f.stat().st_mtime,
        "sha256": "pesha",
    }
    preprocess_items([it], str(d))
    manifest = d / "inputs.manifest.ndjson"
    assert manifest.exists()
    lines = [
        json.loads(line)
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(
        rec.get("binary_format") == "pe" and rec.get("arch") == "x86_64"
        for rec in lines
    )


def test_binary_metadata_wasm(tmp_path: Path):
    d = tmp_path / "case"
    d.mkdir()
    f = d / "m.wasm"
    _write_minimal_wasm(f)
    it = {
        "path": str(f),
        "size": f.stat().st_size,
        "mtime": f.stat().st_mtime,
        "sha256": "wasmsha",
    }
    preprocess_items([it], str(d))
    manifest = d / "inputs.manifest.ndjson"
    assert manifest.exists()
    lines = [
        json.loads(line)
        for line in manifest.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    assert any(rec.get("binary_format") == "wasm" for rec in lines)
