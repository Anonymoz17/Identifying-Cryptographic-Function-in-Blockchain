from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterable, Optional

from .adapter import BaseAdapter, Detection

logger = logging.getLogger(__name__)


class TreeSitterDetector(BaseAdapter):
    """Query-based Tree-sitter detector.

    Behavior:
    - If `tree_sitter` is importable and queries are provided, parse files directly.
    - Otherwise, look for `artifacts/ast/<sha>.json` caches produced by preproc and
      run simple string-based queries or search the cached AST JSON for nodes.
    """

    def __init__(self, queries_dir: Optional[str] = None):
        self.queries_dir = Path(queries_dir) if queries_dir else None
        # best-effort import of tree_sitter; adapters should not hard-fail
        try:
            import tree_sitter as _ts  # type: ignore

            self._ts = _ts
        except Exception:
            self._ts = None

    def _load_query_text(self, language: str) -> Optional[str]:
        if not self.queries_dir:
            return None
        cand = self.queries_dir / f"{language}.scm"
        if cand.exists():
            return cand.read_text(encoding="utf-8")
        return None

    def scan_files(self, files: Iterable[str]):
        for f in files:
            p = Path(f)
            # If tree_sitter available, attempt to parse the source and run queries
            if self._ts:
                try:
                    # try to find a compiled languages library via env var or working dir
                    lib_path = None
                    from os import getenv

                    lib_path = getenv("TREE_SITTER_LANGS")
                    # load per-language Language if available
                    Language = (
                        self._ts.Language if hasattr(self._ts, "Language") else None
                    )
                    Parser = self._ts.Parser if hasattr(self._ts, "Parser") else None
                    if Language and Parser:
                        # determine language name by file extension or preproc metadata
                        lang_name = None
                        # quick ext map
                        ext = p.suffix.lower()
                        if ext in (".sol",):
                            lang_name = "solidity"
                        elif ext in (".go",):
                            lang_name = "go"

                        # load language from combined lib or try to import dynamically
                        ts_lang = None
                        if lib_path:
                            try:
                                ts_lang = Language(lib_path, lang_name)
                            except Exception:
                                ts_lang = None

                        if ts_lang is None:
                            # try to construct a Language from a vendored grammar path (best-effort)
                            try:
                                # This may fail on many systems; treat gracefully
                                repo_lib = Path("tree_sitter_langs.so")
                                if repo_lib.exists() and lang_name:
                                    ts_lang = Language(str(repo_lib), lang_name)
                            except Exception:
                                ts_lang = None

                        if ts_lang:
                            parser = Parser()
                            parser.set_language(ts_lang)
                            try:
                                src = p.read_bytes()
                            except Exception:
                                src = None
                            if src:
                                try:
                                    tree = parser.parse(src)
                                except Exception:
                                    tree = None
                                if tree:
                                    # load the query for this language
                                    qtext = (
                                        self._load_query_text(lang_name)
                                        if lang_name
                                        else None
                                    )
                                    if qtext:
                                        try:
                                            Query = self._ts.Query
                                            query = Query(ts_lang, qtext)
                                            captures = query.captures(tree.root_node)
                                        except Exception:
                                            captures = []

                                        for node, name in captures:
                                            # extract snippet from source by node byte range
                                            snippet = None
                                            try:
                                                snippet = src[
                                                    node.start_byte : node.end_byte
                                                ].decode("utf-8", errors="ignore")
                                            except Exception:
                                                snippet = None
                                            # TODO: map node.start_byte to (line, column) using a source index
                                            # for now we include the byte offset and snippet; production code
                                            # should provide line numbers to improve triage.
                                            details = {
                                                "snippet": snippet or "",
                                                "capture": name,
                                            }
                                            yield Detection(
                                                path=str(p),
                                                offset=node.start_byte,
                                                rule=f"ts:{lang_name}:{name}",
                                                details=details,
                                                engine="tree-sitter",
                                            )
                                    # continue to fallback checks below if no query
                except Exception:
                    logger.debug(
                        "tree_sitter runtime present but parsing failed; falling back to AST cache"
                    )

            # Fallback: look for artifacts/ast/<sha>.json produced by preproc
            if "preproc" in p.parts:
                try:
                    sha = p.parts[p.parts.index("preproc") + 1]
                    ast_path = p.parents[2] / "artifacts" / "ast" / f"{sha}.json"
                except Exception:
                    ast_path = None
            else:
                ast_path = None

            # support a few common AST cache layouts produced by preproc:
            # - <workspace>/artifacts/ast/<sha>.json (preferred)
            # - <workspace>/preproc/<sha>/ast.json (some tests / layouts)
            # - <workspace>/preproc/<sha>/ast/<sha>.json
            candidates = []
            if ast_path:
                candidates.append(ast_path)
            # preproc/<sha>/ast.json
            try:
                preproc_ast = p.parent / "ast.json"
                candidates.append(preproc_ast)
            except Exception:
                pass
            # preproc/<sha>/ast/<sha>.json
            try:
                preproc_ast2 = p.parent / "ast" / f"{sha}.json"
                candidates.append(preproc_ast2)
            except Exception:
                pass

            found_ast = None
            for cand in candidates:
                if cand and cand.exists():
                    found_ast = cand
                    break

            if found_ast:
                try:
                    js = json.loads(found_ast.read_text(encoding="utf-8"))
                except Exception:
                    js = None
                if js:
                    # Apply query heuristics: if queries exist for the language
                    lang = js.get("language") or js.get("lang") or "unknown"
                    qtext = None
                    if self.queries_dir:
                        qtext = self._load_query_text(lang)
                    # naive implementation: stringify AST and search for query tokens
                    s = json.dumps(js)
                    matched = False
                    if qtext:
                        # use first symbol in query as heuristic
                        token = qtext.strip().split()[0]
                        if token and token.lower() in s.lower():
                            details = {"snippet": f"tree-sitter query match: {token}"}
                            yield Detection(
                                path=str(p),
                                offset=None,
                                rule=f"ts:{lang}:{token}",
                                details=details,
                                engine="tree-sitter",
                            )
                            matched = True

                    # always run fallback token scan (helpful when query heuristics miss)
                    for tok in ("keccak", "sha3", "sha256", "aes", "evm"):  # MVP list
                        if tok in s.lower():
                            # avoid duplicating a previous query-match for same token
                            if matched and token and token.lower() == tok:
                                continue
                            details = {"snippet": f"AST contains {tok}"}
                            yield Detection(
                                path=str(p),
                                offset=None,
                                rule=f"ts:{lang}:{tok}",
                                details=details,
                                engine="tree-sitter",
                            )
