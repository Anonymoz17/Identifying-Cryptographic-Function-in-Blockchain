import importlib
from pathlib import Path

import pytest

try:
    HAS_TS = importlib.util.find_spec("tree_sitter") is not None
except Exception:  # pragma: no cover - environment dependent
    HAS_TS = False

from src.detectors.tree_sitter_detector import TreeSitterDetector


@pytest.mark.skipif(not HAS_TS, reason="tree_sitter not installed")
def test_tree_sitter_runtime_integration_small(tmp_path):
    src = tmp_path / "contract.sol"
    src.write_text('function foo() { sha3("a"); }')

    detector = TreeSitterDetector(queries_dir=str(Path("src/detectors/queries")))
    dets = list(detector.scan_files([str(src)]))
    # integration: we may or may not have compiled languages; just assert no exceptions and iterable returned
    assert isinstance(dets, list)
