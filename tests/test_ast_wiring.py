import importlib
import json


def test_build_ast_cache_with_fake_tree_sitter(tmp_path, monkeypatch):
    # Prepare a solidity file with a function definition
    sha = "abab" * 8
    preproc_dir = tmp_path / "preproc" / sha
    preproc_dir.mkdir(parents=True, exist_ok=True)
    sol_path = preproc_dir / "contract.sol"
    sol_text = """
    pragma solidity ^0.8.0;
    contract C {
        function myFunc(uint a) public returns (uint) { return a; }
    }
    """
    sol_path.write_text(sol_text)

    # create a fake tree_sitter_langs.so file so build_ast_cache will attempt to load Language
    libfile = tmp_path / "tree_sitter_langs.so"
    libfile.write_bytes(b"placeholder")

    # make a fake tree_sitter module with Language and Parser
    class FakeChild:
        def __init__(self, start, end):
            self.type = "identifier"
            self.start_byte = start
            self.end_byte = end

    class FakeNode:
        def __init__(self, type_, children=None):
            self.type = type_
            self.children = children or []

    class FakeWalkItem:
        def __init__(self, node):
            self.node = node

    class FakeRoot:
        def __init__(self, text):
            # find 'myFunc' in text for child indices
            idx = text.find("myFunc")
            child = FakeChild(idx, idx + len("myFunc"))
            node = FakeNode("function_definition", children=[child])
            self._items = [FakeWalkItem(node)]

        def walk(self):
            return self._items

    class FakeTree:
        def __init__(self, text):
            self.root_node = FakeRoot(text)

    class FakeParser:
        def __init__(self):
            self.lang = None

        def set_language(self, lang):
            self.lang = lang

        def parse(self, data):
            # data is bytes
            text = data.decode("utf8")
            return FakeTree(text)

    def FakeLanguage(libpath, name):
        # return a simple token representing the language
        return {"lib": libpath, "name": name}

    fake_mod = type("tree_sitter", (), {})()
    # assign attributes directly rather than using setattr (ruff B010 warns)
    fake_mod.Language = FakeLanguage
    fake_mod.Parser = FakeParser

    # inject into sys.modules
    monkeypatch.setitem(importlib.sys.modules, "tree_sitter", fake_mod)

    # call build_ast_cache
    from src.auditor.preproc import build_ast_cache

    build_ast_cache([sha], str(tmp_path))

    out = tmp_path / "artifacts" / "ast" / (sha + ".json")
    assert out.exists()
    data = json.loads(out.read_text())
    assert data.get("sha") == sha
    assert data.get("ast") is not None
    funcs = data["ast"].get("functions")
    assert any(f.get("name") == "myFunc" for f in funcs)
