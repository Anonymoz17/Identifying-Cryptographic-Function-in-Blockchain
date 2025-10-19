import importlib
from pathlib import Path

from src.detectors.tree_sitter_detector import TreeSitterDetector


def _node_for_span(start: int, end: int):
    class Node:
        def __init__(self, s, e):
            self.start_byte = s
            self.end_byte = e

    return Node(start, end)


def test_solidity_precise_captures(tmp_path, monkeypatch):
    # create a source with known line/col offsets
    lines = [
        "pragma solidity ^0.8.0;",
        "contract C {",
        "  function f() public {",
        '    bytes32 h = keccak256(abi.encodePacked("abc"));',
        '    bytes32 h2 = sha256(abi.encodePacked("deadbeef"));',
        "    address a = 0x1234567890abcdef1234567890abcdef12345678;",
        "    address b = 0x00;",
        "  }",
        "}",
    ]
    src = tmp_path / "contract.sol"
    src.write_text("\n".join(lines))

    src_bytes = src.read_bytes()

    # Define byte ranges for the captures we expect. We'll locate substrings.
    keccak_span = (
        src_bytes.find(b"keccak256"),
        src_bytes.find(b"keccak256") + len(b"keccak256"),
    )
    sha256_span = (
        src_bytes.find(b"sha256"),
        src_bytes.find(b"sha256") + len(b"sha256"),
    )
    string_span = (src_bytes.find(b'"abc"'), src_bytes.find(b'"abc"') + len(b'"abc"'))
    hex_span = (
        src_bytes.find(b"0x1234"),
        src_bytes.find(b"0x1234") + len(b"0x1234567890abcdef1234567890abcdef12345678"),
    )
    small_hex_span = (src_bytes.find(b"0x00"), src_bytes.find(b"0x00") + len(b"0x00"))

    class FakeParser:
        def __init__(self):
            pass

        def set_language(self, _):
            pass

        def parse(self, src_bytes_):
            root = _node_for_span(0, len(src_bytes_))

            class Tree:
                root_node = root

            return Tree()

    class FakeQuery:
        def __init__(self, lang, qtext):
            self.qtext = qtext

        def captures(self, root_node):
            # return nodes with specific spans we calculated above
            return [
                (_node_for_span(*keccak_span), "keccak_call"),
                (_node_for_span(*sha256_span), "sha256_call"),
                (_node_for_span(*string_span), "string_literal"),
                (_node_for_span(*hex_span), "hex_literal"),
                (_node_for_span(*small_hex_span), "hex_literal"),
            ]

    FakeTS = type("tree_sitter", (), {})()
    FakeTS.Language = lambda lib, name: object()
    FakeTS.Parser = FakeParser
    FakeTS.Query = FakeQuery

    monkeypatch.setitem(importlib.sys.modules, "tree_sitter", FakeTS)
    monkeypatch.setenv("TREE_SITTER_LANGS", "fake_lib")

    detector = TreeSitterDetector(queries_dir=str(Path("src/detectors/queries")))
    dets = list(detector.scan_files([str(src)]))

    snippets = [d.details.get("snippet") for d in dets]

    assert any("keccak" in (d.rule or "") for d in dets)
    # ensure the string literal snippet contains abc
    assert any("abc" in (s or "") for s in snippets)
    # ensure hex literal captured
    assert any("0x1234" in (s or "") for s in snippets)
    # ensure small hex/address literal captured (0x00)
    assert any("0x00" in (s or "") for s in snippets)
    # ensure number/numeric-like literals captured somewhere
    assert any(any(ch.isdigit() for ch in (s or "")) for s in snippets)
