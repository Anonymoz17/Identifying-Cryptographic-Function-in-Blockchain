import importlib
from pathlib import Path

from src.detectors.tree_sitter_detector import TreeSitterDetector


def test_tree_sitter_runtime_parses_and_returns_captures(tmp_path, monkeypatch):
    # create a fake source file
    src = tmp_path / "contract.sol"
    src.write_text('function foo() { sha3("a"); }')

    # create a fake tree_sitter module
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
            # pretend entire file is a node
            root = FakeNode(0, len(src_bytes))

            class Tree:
                root_node = root

            return Tree()

    class FakeQuery:
        def __init__(self, lang, qtext):
            pass

        def captures(self, root_node):
            # return a single capture mapping to the whole source
            return [(root_node, "sha3_call")]

    FakeTS = type("tree_sitter", (), {})()
    FakeTS.Language = lambda lib, name: object()
    FakeTS.Parser = FakeParser
    FakeTS.Query = FakeQuery

    monkeypatch.setitem(importlib.sys.modules, "tree_sitter", FakeTS)
    # make the detector attempt to load a Language via the env var path
    monkeypatch.setenv("TREE_SITTER_LANGS", "fake_lib")

    detector = TreeSitterDetector(queries_dir=str(Path("src/detectors/queries")))
    dets = list(detector.scan_files([str(src)]))
    assert any(
        d.rule.startswith("ts:solidity:") or d.details.get("capture") == "sha3_call"
        for d in dets
    )


def test_tree_sitter_runtime_skips_if_no_library(tmp_path):
    # if tree_sitter not present, detector should still construct
    detector = TreeSitterDetector(queries_dir=None)
    assert detector is not None
