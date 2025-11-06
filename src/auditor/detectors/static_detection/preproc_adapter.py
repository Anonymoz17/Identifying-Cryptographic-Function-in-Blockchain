"""Preproc adapter: deterministic loading and validation of preproc artifacts.

This module provides a minimal `load_preproc` function that will be used by
the runner and unit tests. The real implementation should perform schema
checks and return a structured object.
"""
from typing import Dict, Any
import os
import json
import hashlib


def _sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_preproc(preproc_dir: str) -> Dict[str, Any]:
    """Load and validate preproc artifacts from `preproc_dir`.

    Returns a dict with:
      - file_hash: computed SHA256 of input.bin
      - input_path: absolute path to input.bin
      - metadata_path: absolute path to metadata.json
      - metadata: parsed metadata dict
      - size: size in bytes of input.bin

    Raises FileNotFoundError if required artifacts are missing. Raises
    ValueError if metadata contains a conflicting `file_hash` value.
    """
    input_path = os.path.join(preproc_dir, "input.bin")
    metadata_path = os.path.join(preproc_dir, "metadata.json")

    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"preproc input not found: {input_path}")
    if not os.path.isfile(metadata_path):
        raise FileNotFoundError(f"preproc metadata not found: {metadata_path}")

    with open(metadata_path, "r", encoding="utf-8") as fh:
        try:
            metadata = json.load(fh)
        except Exception as exc:  # pragma: no cover - defensive
            raise ValueError(f"failed to parse metadata.json: {exc}") from exc

    computed_hash = _sha256_of_file(input_path)
    size = os.path.getsize(input_path)

    # If metadata contains a hash, ensure it matches computed
    meta_hash = metadata.get("file_hash") or metadata.get("sha256")
    if meta_hash and meta_hash != computed_hash:
        raise ValueError(
            f"preproc metadata file_hash mismatch: metadata={meta_hash} computed={computed_hash}"
        )

    file_hash = computed_hash

    return {
        "file_hash": file_hash,
        "input_path": input_path,
        "metadata_path": metadata_path,
        "metadata": metadata,
        "size": size,
    }
