import sys
from pathlib import Path


def test_build_ast_cache_with_fake_treesitter(tmp_path: Path, monkeypatch):
    # create fake tree_sitter module
    fake_ts = type(sys)("tree_sitter")

    class FakeLanguage:
        def __init__(self, lib, name):
            pass

    class FakeParser:
        def set_language(self, lang):
            pass

        def parse(self, data):
            class Node:
                def __init__(self):
                    self.children = []

            class Tree:
                root_node = Node()

            return Tree()

    fake_ts.Language = FakeLanguage
    fake_ts.Parser = FakeParser
    monkeypatch.setitem(sys.modules, "tree_sitter", fake_ts)

    # create a preproc input file to be parsed
    sha = "deadbeef"
    preproc_dir = tmp_path / "preproc" / sha
    preproc_dir.mkdir(parents=True, exist_ok=True)
    (preproc_dir / "input.bin").write_text("function foo() {}")

    # import and call
    from src.auditor.preproc import build_ast_cache

    build_ast_cache([sha], str(tmp_path))
    assert (tmp_path / "artifacts" / "ast" / (sha + ".json")).exists()


def test_build_disasm_cache_with_fake_capstone(tmp_path: Path, monkeypatch):
    # fake capstone module
    fake_cs = type(sys)("capstone")

    class FakeCsClass:
        def __init__(self, arch, mode):
            pass

        def disasm(self, data, base):
            class Insn:
                def __init__(self):
                    self.address = 0
                    self.mnemonic = "mov"
                    self.op_str = "eax, ebx"

            return [Insn()]

    fake_cs.Cs = FakeCsClass
    fake_cs.CS_ARCH_X86 = 1
    fake_cs.CS_MODE_64 = 2
    fake_cs.CS_MODE_32 = 3
    monkeypatch.setitem(sys.modules, "capstone", fake_cs)

    sha = "cafebabe"
    preproc_dir = tmp_path / "preproc" / sha
    preproc_dir.mkdir(parents=True, exist_ok=True)
    (preproc_dir / "input.bin").write_bytes(b"\x90\x90\x90")

    from src.auditor.preproc import build_disasm_cache

    build_disasm_cache([sha], str(tmp_path))
    assert (tmp_path / "artifacts" / "disasm" / (sha + ".json")).exists()
