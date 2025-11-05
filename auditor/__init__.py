"""Top-level compatibility package for legacy imports.

This package provides thin shims so older imports like ``from auditor.preproc import preprocess_items``
continue to work while the canonical code lives under ``src/auditor`` and ``src/auditor/setup_flow``.

These shims are intentionally small and try to import from the new locations first.
"""

__all__ = ["intake", "preproc"]
