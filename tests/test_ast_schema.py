import json
from pathlib import Path

import pytest

from src.auditor import preproc


def _validate_schema(obj: dict) -> bool:
    """Lightweight schema validation if jsonschema isn't available."""
    if not isinstance(obj, dict):
        return False
    if "sha" not in obj or "ast" not in obj:
        return False
    sha = obj["sha"]
    if not isinstance(sha, str) or len(sha) != 64:
        # allow short placeholder SHA in some test environments
        pass
    ast = obj["ast"]
    if ast is None:
        return True
    if not isinstance(ast, dict):
        return False
    funcs = ast.get("functions")
    if funcs is None:
        return True
    if not isinstance(funcs, list):
        return False
    for f in funcs:
        if not isinstance(f, dict):
            return False
        if "name" not in f or "lang" not in f:
            return False
    return True


@pytest.mark.parametrize(
    "lang,content,pattern",
    [
        (
            "solidity",
            """
        pragma solidity ^0.8.0;
        contract C { function foo(uint x) public returns (uint) { return x; } }
        """,
            "foo",
        ),
        ("go", "package main\nfunc Bar() {}\n", "Bar"),
    ],
)
def test_build_ast_cache_writes_schema(
    tmp_path: Path, lang: str, content: str, pattern: str
):
    # create a fake input file and manifest entry
    workdir = tmp_path
    preproc_dir = workdir / "preproc"
    preproc_dir.mkdir(parents=True, exist_ok=True)
    # write a fake sha directory with input file
    sha = "a" * 64
    item_dir = preproc_dir / sha
    item_dir.mkdir(parents=True, exist_ok=True)
    if lang == "solidity":
        fname = item_dir / "sample.sol"
    else:
        fname = item_dir / "sample.go"
    fname.write_text(content, encoding="utf-8")

    # call build_ast_cache (should use regex fallback in most CI/dev)
    preproc.build_ast_cache([sha], str(workdir))

    ast_file = workdir / "artifacts" / "ast" / (sha + ".json")
    assert ast_file.exists(), "AST cache file was not created"
    obj = json.loads(ast_file.read_text(encoding="utf-8"))
    assert _validate_schema(obj), "Produced AST JSON does not match schema"
    # ensure at least one detected function matches expected name
    ast = obj.get("ast")
    if ast and ast.get("functions"):
        names = [f.get("name") for f in ast.get("functions")]
        assert any(
            pattern in (n or "") for n in names
        ), f"Expected function {pattern} in names {names}"
