import json
from pathlib import Path

from src.auditor.preproc import build_ast_cache, preprocess_items


def test_ast_cache_solidity(tmp_path: Path):
    d = tmp_path / "case"
    d.mkdir()
    f = d / "contract.sol"
    f.write_text(
        """
    pragma solidity ^0.8.0;
    contract C {
        function foo(uint x) public returns (uint) { return x; }
    }
    """
    )
    it = {
        "path": str(f),
        "size": f.stat().st_size,
        "mtime": f.stat().st_mtime,
        "sha256": "solsha",
    }
    preprocess_items([it], str(d))
    build_ast_cache(["solsha"], str(d))
    astf = d / "artifacts" / "ast" / ("solsha" + ".json")
    assert astf.exists()
    obj = json.loads(astf.read_text(encoding="utf-8"))
    assert obj.get("ast") and any(
        f.get("name") == "foo" for f in obj["ast"]["functions"]
    )


def test_ast_cache_go(tmp_path: Path):
    d = tmp_path / "case"
    d.mkdir()
    f = d / "main.go"
    f.write_text(
        """
    package main
    import "fmt"
    func Bar() {
        fmt.Println("bar")
    }
    """
    )
    it = {
        "path": str(f),
        "size": f.stat().st_size,
        "mtime": f.stat().st_mtime,
        "sha256": "gosha",
    }
    preprocess_items([it], str(d))
    build_ast_cache(["gosha"], str(d))
    astf = d / "artifacts" / "ast" / ("gosha" + ".json")
    assert astf.exists()
    obj = json.loads(astf.read_text(encoding="utf-8"))
    assert obj.get("ast") and any(
        f.get("name") == "Bar" for f in obj["ast"]["functions"]
    )
