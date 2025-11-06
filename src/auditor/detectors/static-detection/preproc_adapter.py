"""Adapters to read and validate preproc artifacts.

Expecting a directory `preproc/<file_hash>/` containing at minimum:
- input.bin
- metadata.json

This module provides a small helper to load metadata and canonical paths.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, Any


class PreprocError(Exception):
    pass


def load_preproc(preproc_dir: str) -> Dict[str, Any]:
    """Load and validate the preproc artifact directory.

    Args:
        preproc_dir: path to preproc/<file_hash> directory

    Returns:
        dict with keys: file_hash, input_path, metadata (dict)

    Raises:
        PreprocError if expected files are missing or invalid.
    """
    p = Path(preproc_dir)
    if not p.exists() or not p.is_dir():
        raise PreprocError(f"preproc directory not found: {preproc_dir}")

    input_path = p / "input.bin"
    metadata_path = p / "metadata.json"

    if not input_path.exists():
        raise PreprocError(f"input.bin not found in {preproc_dir}")
    if not metadata_path.exists():
        raise PreprocError(f"metadata.json not found in {preproc_dir}")

    try:
        with metadata_path.open("r", encoding="utf-8") as fh:
            metadata = json.load(fh)
    except Exception as e:  # keep broad to report parsing issues
        raise PreprocError(f"failed to read metadata.json: {e}")

    file_hash = metadata.get("sha256") or metadata.get("id") or p.name

    return {
        "file_hash": file_hash,
        "preproc_dir": str(p),
        "input_path": str(input_path),
        "metadata": metadata,
    }


def ensure_output_dir(base: str) -> str:
    d = Path(base)
    d.mkdir(parents=True, exist_ok=True)
    return str(d)
