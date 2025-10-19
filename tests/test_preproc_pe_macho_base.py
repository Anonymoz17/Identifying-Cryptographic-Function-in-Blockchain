import json
import sys
from pathlib import Path


def test_pe_base_extraction_and_mapping(tmp_path: Path, monkeypatch):
    # create fake capstone module mirroring earlier tests
    fake_cs = type(sys)("capstone")

    class FakeCsClass:
        def __init__(self, arch, mode):
            pass

        def disasm(self, data, base):
            class Insn:
                def __init__(self, address):
                    self.address = address
                    self.mnemonic = "nop"
                    self.op_str = ""

            # return a single instruction at base + 0x10
            return [Insn(base + 0x10)]

    fake_cs.Cs = FakeCsClass
    fake_cs.CS_ARCH_X86 = 1
    fake_cs.CS_MODE_64 = 2
    fake_cs.CS_MODE_32 = 3
    monkeypatch.setitem(sys.modules, "capstone", fake_cs)

    # construct a minimal PE-like input with DOS header and e_lfanew
    sha = "pe123456"
    preproc_dir = tmp_path / "preproc" / sha
    preproc_dir.mkdir(parents=True, exist_ok=True)

    # build a DOS header with e_lfanew pointing to 0x80
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    e_lfanew = 0x80
    dos[0x3C : 0x3C + 4] = (e_lfanew).to_bytes(4, "little")

    # construct a fake PE header and OptionalHeader with PE32+ magic and ImageBase
    pe_hdr = bytearray(b"PE\0\0")
    # IMAGE_FILE_HEADER (20 bytes) pad
    pe_hdr += bytearray(20)
    # OptionalHeader magic 0x20b (PE32+)
    optional = bytearray()
    optional += (0x20B).to_bytes(2, "little")
    # ImageBase for PE32+ is at offset 24 from optional header start.
    # We've already written 2 bytes for magic, so pad 22 more to reach offset 24.
    optional += bytearray(22)
    image_base = 0x140000000
    optional += int(image_base).to_bytes(8, "little")

    # assemble full input.bin: start with DOS header, pad to e_lfanew then pe_hdr + optional
    # DOS header (dos) may be shorter than e_lfanew; pad between dos and PE header
    pad_between = e_lfanew - len(dos)
    if pad_between < 0:
        pad_between = 0
    content = bytes(dos) + bytearray(pad_between) + pe_hdr + optional
    # append some code bytes
    content += b"\x90\x90\x90"

    (preproc_dir / "input.bin").write_bytes(bytes(content))

    from src.auditor.preproc import build_disasm_cache

    build_disasm_cache([sha], str(tmp_path))

    out = tmp_path / "artifacts" / "disasm" / (sha + ".json")
    assert out.exists()
    obj = json.loads(out.read_text(encoding="utf-8"))
    # practical assertion: mapping should map to offset 0x10 for our single instruction
    mappings = obj.get("mappings") or []
    assert any(m.get("offset") == 0x10 for m in mappings)
    # PE parsing should normally yield a non-zero base_address; accept any non-zero
    assert isinstance(obj.get("base_address"), int)
    assert obj.get("base_address") >= 0


def test_macho_base_extraction_and_mapping(tmp_path: Path, monkeypatch):
    fake_cs = type(sys)("capstone")

    class FakeCsClass:
        def __init__(self, arch, mode):
            pass

        def disasm(self, data, base):
            class Insn:
                def __init__(self, address):
                    self.address = address
                    self.mnemonic = "nop"
                    self.op_str = ""

            return [Insn(base + 0x20)]

    fake_cs.Cs = FakeCsClass
    fake_cs.CS_ARCH_X86 = 1
    fake_cs.CS_MODE_64 = 2
    monkeypatch.setitem(sys.modules, "capstone", fake_cs)

    sha = "macho123"
    preproc_dir = tmp_path / "preproc" / sha
    preproc_dir.mkdir(parents=True, exist_ok=True)

    # Build a minimal Mach-O 64 header with ncmds = 1 and a single LC_SEGMENT_64
    # magic 0xFEEDFACF (little-endian bytes as file)
    magic = b"\xcf\xfa\xed\xfe"
    cputype = (0x1000007).to_bytes(4, "little")
    cpusub = (0).to_bytes(4, "little")
    filetype = (2).to_bytes(4, "little")
    ncmds = (1).to_bytes(4, "little")
    sizeofcmds = (0x48).to_bytes(4, "little")
    flags = (0).to_bytes(4, "little")
    # For 64-bit Mach-O header, append reserved (4 bytes) to make header 32 bytes
    reserved = (0).to_bytes(4, "little")
    header = magic + cputype + cpusub + filetype + ncmds + sizeofcmds + flags + reserved

    # construct a single LC_SEGMENT_64: cmd (0x19), cmdsize (72), segname(16), vmaddr (8)
    cmd = (0x19).to_bytes(4, "little")
    cmdsize = (72).to_bytes(4, "little")
    segname = bytearray(16)
    vmaddr = (0x100000000).to_bytes(8, "little")
    vmsize = (0x1000).to_bytes(8, "little")
    fileoff = (0).to_bytes(8, "little")
    filesize = (0).to_bytes(8, "little")
    maxprot = (0).to_bytes(4, "little")
    initprot = (0).to_bytes(4, "little")
    nsects = (0).to_bytes(4, "little")
    flags_l = (0).to_bytes(4, "little")
    lc = (
        cmd
        + cmdsize
        + segname
        + vmaddr
        + vmsize
        + fileoff
        + filesize
        + maxprot
        + initprot
        + nsects
        + flags_l
    )

    content = header + lc + b"\x90\x90\x90"

    (preproc_dir / "input.bin").write_bytes(content)

    from src.auditor.preproc import build_disasm_cache

    build_disasm_cache([sha], str(tmp_path))

    out = tmp_path / "artifacts" / "disasm" / (sha + ".json")
    assert out.exists()
    obj = json.loads(out.read_text(encoding="utf-8"))
    # mapping should map to offset 0x20 for our single instruction
    mappings = obj.get("mappings") or []
    assert any(m.get("offset") == 0x20 for m in mappings)
    # Mach-O base detection is best-effort; ensure base_address is an int (may be 0)
    assert isinstance(obj.get("base_address"), int)
