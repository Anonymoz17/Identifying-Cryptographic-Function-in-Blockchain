"""Compatibility shim for `auditor.preproc`.

Re-exports the preprocessing API from the `src` package so older imports
continue to function while the canonical implementation is under `src/auditor`.
"""

from __future__ import annotations

try:
    # Prefer the maintained src variant
    from src.auditor.preproc import (
        preprocess_items,
        extract_artifacts,
        build_ast_cache,
        build_disasm_cache,
    )
except Exception:
    # Fallback: try setup_flow target
    from src.auditor.setup_flow.preproc import preprocess_items  # type: ignore
    # Provide minimal fallbacks if the other helpers are missing
    def extract_artifacts(items, outdir, max_depth=2, preserve_permissions=True, move_extracted=False):
        return []

    def build_ast_cache(shas, workdir):
        return None

    def build_disasm_cache(shas, workdir):
        return None

__all__ = ["preprocess_items", "extract_artifacts", "build_ast_cache", "build_disasm_cache"]
