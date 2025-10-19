import json
from pathlib import Path

from src.detectors.tree_sitter_detector import TreeSitterDetector


def test_tree_sitter_detector_reads_ast(tmp_path):
    # create fake preproc layout
    wd = tmp_path
    preproc = wd / "preproc"
    sha = "fake123"
    art_dir = preproc / sha
    art_dir.mkdir(parents=True)
    # write a fake AST JSON that should trigger 'sha3' match
    ast = {
        "language": "solidity",
        "nodes": [{"type": "call_expression", "text": "sha3(...)"}],
    }
    (art_dir / "metadata.json").write_text(json.dumps(ast))
    (art_dir / "ast.json").write_text(json.dumps(ast))

    # create a dummy input.bin path for scanner mapping
    inp = art_dir / "input.bin"
    inp.write_bytes(b"\x00")

    detector = TreeSitterDetector(queries_dir=str(Path("detectors/queries")))
    dets = list(detector.scan_files([str(inp)]))
    assert any("sha3" in (d.details.get("snippet") or "") for d in dets)
