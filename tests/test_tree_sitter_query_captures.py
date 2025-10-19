import importlib
from pathlib import Path

from src.detectors.tree_sitter_detector import TreeSitterDetector


def test_query_captures_map_to_detections(monkeypatch, tmp_path):
    src = tmp_path / "contract.sol"
    src.write_text('function foo() { keccak256("x"); ecrecover(...); }')

    class FakeNode:
        def __init__(self, start_byte, end_byte):
            self.start_byte = start_byte
            self.end_byte = end_byte

    class FakeParser:
        def set_language(self, _):
            pass

        def parse(self, src_bytes):
            root = FakeNode(0, len(src_bytes))

            class Tree:
                root_node = root

            return Tree()

    class FakeQuery:
        def __init__(self, lang, qtext):
            pass

        def captures(self, root_node):
            # two captures with different names
            return [(root_node, "sha_call"), (root_node, "ec_call")]

    FakeTS = type("tree_sitter", (), {})()
    FakeTS.Language = lambda lib, name: object()
    FakeTS.Parser = FakeParser
    FakeTS.Query = FakeQuery

    monkeypatch.setitem(importlib.sys.modules, "tree_sitter", FakeTS)
    monkeypatch.setenv("TREE_SITTER_LANGS", "fake_lib")

    detector = TreeSitterDetector(queries_dir=str(Path("src/detectors/queries")))
    dets = list(detector.scan_files([str(src)]))
    names = {d.rule for d in dets}
    assert any("sha_call" in n or "ec_call" in n for n in names)
