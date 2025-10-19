import importlib
from pathlib import Path

from src.detectors.tree_sitter_detector import TreeSitterDetector


def test_no_false_positives(tmp_path, monkeypatch):
    # source that shouldn't match crypto queries
    src = tmp_path / "safe.sol"
    # include a comment containing '0x' followed by non-address chars to ensure
    # our address regex isn't over-greedy
    src.write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.0;",
                "contract Safe {",
                "  function noop() public {",
                "    uint x = 1 + 2;",
                '    string s = "hello";',
                "    // not an address: 0xdead",
                "  }",
                "}",
            ]
        )
    )

    # fake Query that returns no captures
    class FakeParser:
        def __init__(self):
            pass

        def set_language(self, _):
            pass

        def parse(self, src_bytes):
            class Tree:
                root_node = type(
                    "N", (), {"start_byte": 0, "end_byte": len(src_bytes)}
                )()

            return Tree()

    class FakeQuery:
        def __init__(self, lang, qtext):
            pass

        def captures(self, root_node):
            return []

    FakeTS = type("tree_sitter", (), {})()
    FakeTS.Language = lambda lib, name: object()
    FakeTS.Parser = FakeParser
    FakeTS.Query = FakeQuery

    monkeypatch.setitem(importlib.sys.modules, "tree_sitter", FakeTS)
    monkeypatch.setenv("TREE_SITTER_LANGS", "fake_lib")

    detector = TreeSitterDetector(queries_dir=str(Path("src/detectors/queries")))
    dets = list(detector.scan_files([str(src)]))
    # ensure no crypto detections
    assert all(not (d.rule.startswith("ts:solidity:")) for d in dets)


def test_nested_member_expression_detects_abi_encode(tmp_path, monkeypatch):
    src = tmp_path / "nested.sol"
    src.write_text(
        "\n".join(
            [
                "pragma solidity ^0.8.0;",
                "contract C {",
                "  function f() public {",
                "    Lib.Abi abi; // pretend nested",
                '    bytes32 h = Lib.abi.encodePacked("x");',
                "  }",
                "}",
            ]
        )
    )

    src_bytes = src.read_bytes()

    # find position of encodePacked substring
    enc_pos = src_bytes.find(b"encodePacked")
    enc_span = (enc_pos, enc_pos + len(b"encodePacked"))

    class FakeParser:
        def __init__(self):
            pass

        def set_language(self, _):
            pass

        def parse(self, src_bytes_):
            class Tree:
                root_node = type(
                    "N", (), {"start_byte": 0, "end_byte": len(src_bytes_)}
                )()

            return Tree()

    class FakeQuery:
        def __init__(self, lang, qtext):
            self.qtext = qtext

        def captures(self, root_node):
            return [(_node for _node in [])]

    # To simulate capture we will return a node with the encodePacked span
    class CapQuery:
        def __init__(self, lang, qtext):
            pass

        def captures(self, root_node):
            class Node:
                def __init__(self, s, e):
                    self.start_byte = s
                    self.end_byte = e

            return [(Node(*enc_span), "keccak_call")]

    FakeTS = type("tree_sitter", (), {})()
    FakeTS.Language = lambda lib, name: object()
    FakeTS.Parser = FakeParser
    FakeTS.Query = CapQuery

    monkeypatch.setitem(importlib.sys.modules, "tree_sitter", FakeTS)
    monkeypatch.setenv("TREE_SITTER_LANGS", "fake_lib")

    detector = TreeSitterDetector(queries_dir=str(Path("src/detectors/queries")))
    dets = list(detector.scan_files([str(src)]))

    assert any(
        "encodePacked" in (d.details.get("snippet") or "")
        or d.rule.startswith("ts:solidity:")
        for d in dets
    )
