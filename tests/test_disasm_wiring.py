import importlib
import json


def test_build_disasm_cache_with_fake_capstone(tmp_path, monkeypatch):
    # create a fake capstone module
    class FakeInsn:
        def __init__(self, address, mnemonic, op_str):
            self.address = address
            self.mnemonic = mnemonic
            self.op_str = op_str

    class FakeCs:
        def __init__(self, arch, mode):
            pass

        def disasm(self, data, addr):
            # simple fake: return two instructions
            return [FakeInsn(0, "mov", "eax, ebx"), FakeInsn(1, "ret", "")]

    fake_capstone = type("capstone", (), {})()
    # assign attributes directly
    fake_capstone.Cs = FakeCs
    fake_capstone.CS_ARCH_X86 = 1
    fake_capstone.CS_MODE_64 = 2

    # inject into sys.modules
    monkeypatch.setitem(importlib.sys.modules, "capstone", fake_capstone)

    # create a fake preproc input bin
    sha = "deadbeef" * 4
    preproc_dir = tmp_path / "preproc" / sha
    preproc_dir.mkdir(parents=True, exist_ok=True)
    bin_path = preproc_dir / "input.bin"
    bin_path.write_bytes(b"\x90\x90\xc3")

    # call build_disasm_cache (imported from module under test)
    from src.auditor.preproc import build_disasm_cache

    build_disasm_cache([sha], str(tmp_path))

    out = tmp_path / "artifacts" / "disasm" / (sha + ".json")
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["sha"] == sha
    assert isinstance(data.get("disasm"), list)
