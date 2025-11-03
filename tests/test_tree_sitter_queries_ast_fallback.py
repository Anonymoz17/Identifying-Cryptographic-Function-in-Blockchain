import json
from pathlib import Path

from src.detectors.tree_sitter_detector import TreeSitterDetector


def test_ast_fallback_detects_keccak(tmp_path):
    preproc = tmp_path / "preproc"
    sha = "fakeabc"
    art_dir = preproc / sha
    art_dir.mkdir(parents=True)

    # craft a minimal AST JSON that includes a call_expression text with keccak
    ast = {
        "language": "solidity",
        "nodes": [{"type": "call_expression", "text": "keccak256(...)"}],
    }
    (art_dir / "metadata.json").write_text(json.dumps(ast))
    (art_dir / "ast.json").write_text(json.dumps(ast))

    # dummy input.bin for mapping
    inp = art_dir / "input.bin"
    inp.write_bytes(b"\x00")

    detector = TreeSitterDetector(queries_dir=str(Path("detectors/queries")))
    dets = list(detector.scan_files([str(inp)]))
    assert any(
        "keccak" in (d.details.get("snippet") or "")
        or "sha3" in (d.details.get("snippet") or "")
        for d in dets
    )
