from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from .adapter import BaseAdapter, Detection


class TreeSitterJsonExample(BaseAdapter):
    """Example adapter that reads `artifacts/ast/<sha>.json` and emits simple
    structural matches by searching the cached AST JSON for node types/strings.
    This is intentionally lightweight and intended as an MVP example for auditors.
    """

    def __init__(self, query: str | None = None):
        # query is a simple substring to search within AST node 'type' or 'text'
        self.query = query or "crypt"

    def scan_files(self, files: Iterable[str]):
        for f in files:
            p = Path(f)
            # map preproc/<sha>/input.bin -> artifacts/ast/<sha>.json
            if "preproc" in p.parts:
                try:
                    sha = p.parts[p.parts.index("preproc") + 1]
                    ast_path = p.parents[2] / "artifacts" / "ast" / f"{sha}.json"
                except Exception:
                    ast_path = None
            else:
                ast_path = None

            if ast_path and ast_path.exists():
                try:
                    js = json.loads(ast_path.read_text(encoding="utf-8"))
                except Exception:
                    js = None
                if js:
                    # naive traversal: stringify and search; replace with proper queries for real detectors
                    s = json.dumps(js)
                    if self.query.lower() in s.lower():
                        details = {"snippet": f"AST contains {self.query}"}
                        yield Detection(
                            path=str(f),
                            offset=None,
                            rule="tree_sitter_example",
                            details=details,
                            engine="tree-sitter",
                        )
