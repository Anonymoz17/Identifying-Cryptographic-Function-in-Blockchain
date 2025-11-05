"""Compatibility package mapping for `auditor.setup_flow` -> `src.auditor.setup_flow`.

This module imports the real implementation under `src.auditor.setup_flow` and
registers its submodules under the `auditor.setup_flow.*` names so tests and
callers that import `auditor.setup_flow.preproc` continue to work.
"""

from __future__ import annotations

import importlib
import sys

_SRC_PKG = "src.auditor.setup_flow"
try:
    _src = importlib.import_module(_SRC_PKG)
except Exception:
    # If the src package isn't importable, defer errors to the real imports
    _src = None

# Register known submodules so `import auditor.setup_flow.preproc` works
_known_subs = [
    "preproc",
    "manifest",
    "setupcontext",
    "setupmessages",
    "persistence",
    "hash_dedupe",
    "archives",
    "output",
    "validation",
    "progress",
    "runner",
]

if _src is not None:
    for s in _known_subs:
        try:
            m = importlib.import_module(f"{_SRC_PKG}.{s}")
            sys.modules[f"auditor.setup_flow.{s}"] = m
        except Exception:
            # ignore missing optional submodules
            pass

# re-export top-level attributes from the src package for convenience
if _src is not None:
    for name in dir(_src):
        if name.startswith("_"):
            continue
        try:
            globals()[name] = getattr(_src, name)
        except Exception:
            pass

__all__ = getattr(_src, "__all__", []) if _src is not None else []
