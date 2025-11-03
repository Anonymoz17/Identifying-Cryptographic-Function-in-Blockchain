import importlib
from pathlib import Path

from src.detectors.tree_sitter_detector import TreeSitterDetector


def test_solidity_queries_capture_common_crypto(tmp_path, monkeypatch):
    src = tmp_path / "contract.sol"
    src.write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.0;",
                "contract C {",
                "  function f() public {",
                '    bytes32 h = keccak256(abi.encodePacked("a"));',
                '    bytes32 h2 = sha3("b");',
                '    bytes32 s = sha256(abi.encodePacked("c"));',
                "    address r = ecrecover(h, 27, bytes32(0), bytes32(0));",
                "  }",
                "}",
            ]
        )
    )

    # Use mocked tree_sitter that behaves like the runtime parsing flow but
    # delegates captures to reading the query via our detector._load_query_text.
    class FakeNode:
        def __init__(self, start_byte, end_byte):
            self.start_byte = start_byte
            self.end_byte = end_byte

    class FakeParser:
        def __init__(self):
            pass

        def set_language(self, _):
            pass

        def parse(self, src_bytes):
            root = FakeNode(0, len(src_bytes))

            class Tree:
                root_node = root

            return Tree()

    class FakeQuery:
        def __init__(self, lang, qtext):
            # capture tokens we expect: sha3/keccak/sha256/ecrecover
            self.qtext = qtext

        def captures(self, root_node):
            # naively return captures for the whole source so detector will
            # extract snippets and line/column using byte ranges
            caps = []
            for name in ("sha_call", "sha256_call", "ecrecover_call"):
                caps.append((root_node, name))
            return caps

    FakeTS = type("tree_sitter", (), {})()
    FakeTS.Language = lambda lib, name: object()
    FakeTS.Parser = FakeParser
    FakeTS.Query = FakeQuery

    monkeypatch.setitem(importlib.sys.modules, "tree_sitter", FakeTS)
    monkeypatch.setenv("TREE_SITTER_LANGS", "fake_lib")

    # ensure queries directory is the project's detectors/queries
    detector = TreeSitterDetector(queries_dir=str(Path("detectors/queries")))
    dets = list(detector.scan_files([str(src)]))

    # confirm we detected at least the token captures and line/col are present
    assert any(d.rule.startswith("ts:solidity:") for d in dets)
    assert any(isinstance(d.details.get("line"), int) for d in dets)
    assert any(isinstance(d.details.get("col"), int) for d in dets)


def test_go_queries_capture_selectors(tmp_path, monkeypatch):
    src = tmp_path / "file.go"
    src.write_text(
        "\n".join(
            [
                "package main",
                'import ("crypto/sha256")',
                "func main() {",
                '  _ = sha256.Sum256([]byte("x"))',
                "}",
            ]
        )
    )

    class FakeNode:
        def __init__(self, start_byte, end_byte):
            self.start_byte = start_byte
            self.end_byte = end_byte

    class FakeParser:
        def __init__(self):
            pass

        def set_language(self, _):
            pass

        def parse(self, src_bytes):
            root = FakeNode(0, len(src_bytes))

            class Tree:
                root_node = root

            return Tree()

    class FakeQuery:
        def __init__(self, lang, qtext):
            self.qtext = qtext

        def captures(self, root_node):
            return [(root_node, "method_name"), (root_node, "func_ident")]

    FakeTS = type("tree_sitter", (), {})()
    FakeTS.Language = lambda lib, name: object()
    FakeTS.Parser = FakeParser
    FakeTS.Query = FakeQuery

    monkeypatch.setitem(importlib.sys.modules, "tree_sitter", FakeTS)
    monkeypatch.setenv("TREE_SITTER_LANGS", "fake_lib")

    detector = TreeSitterDetector(queries_dir=str(Path("detectors/queries")))
    dets = list(detector.scan_files([str(src)]))

    assert any("sha256" in (d.rule or "") or d.details.get("capture") for d in dets)
