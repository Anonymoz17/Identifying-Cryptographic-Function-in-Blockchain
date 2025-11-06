"""Minimal Ghidra headless adapter (stub).

This module provides a lightweight wrapper API for running or reading a cached
Ghidra export for a given preproc artifact. In this initial skeleton we do not
execute Ghidra automatically; instead we look for an existing export under
`ghidra_export_dir` and return its path if present. The actual headless
invocation will be implemented in a later iteration.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional


def find_cached_export(ghidra_export_dir: str, file_hash: str) -> Optional[str]:
    """Return path to cached ghidra export JSON if present.

    Expected layout: ghidra_export_dir/<file_hash>/functions.json
    """
    p = Path(ghidra_export_dir) / file_hash / "functions.json"
    if p.exists():
        return str(p)
    return None


def read_ghidra_functions(export_json_path: str) -> Dict[str, Any]:
    """Read functions exported by a Ghidra script (JSON).

    The exact shape is implementation-defined; this helper returns the parsed JSON
    as a dict so the static detector can consume it.
    """
    p = Path(export_json_path)
    with p.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def run_ghidra_headless_stub(preproc_input: str, ghidra_export_dir: str, file_hash: str) -> str:
    """Stub that documents intended behavior and returns path to export.

    Real implementation will:
      - locate analyzeHeadless (GHIDRA_INSTALL_DIR or PATH)
      - invoke it with our Ghidra script to export functions
      - write results to ghidra_export_dir/<file_hash>/functions.json

    For now, this creates an empty export if none exists to allow downstream
    development without actually running Ghidra.
    """
    out_dir = Path(ghidra_export_dir) / file_hash
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "functions.json"

    if not out_path.exists():
        # produce a minimal placeholder export
        placeholder = {"file_hash": file_hash, "functions": []}
        with out_path.open("w", encoding="utf-8") as fh:
            json.dump(placeholder, fh, indent=2)

    return str(out_path)
