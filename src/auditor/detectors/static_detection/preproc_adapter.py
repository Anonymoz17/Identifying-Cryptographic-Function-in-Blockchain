"""Preproc adapter: deterministic loading and validation of preproc artifacts.

This module provides a minimal `load_preproc` function that will be used by
the runner and unit tests. The real implementation should perform schema
checks and return a structured object.
"""
from typing import Dict, Any
import os
import json
import hashlib
from dataclasses import dataclass
import importlib
import importlib.util
import types


@dataclass
class Preproc:
    file_hash: str
    input_path: str
    metadata_path: str
    metadata: Dict[str, Any]
    size: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_hash": self.file_hash,
            "input_path": self.input_path,
            "metadata_path": self.metadata_path,
            "metadata": self.metadata,
            "size": self.size,
        }


def _sha256_of_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def load_preproc(preproc_dir: str) -> Preproc:
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
    # Normalize and canonicalize paths
    preproc_dir = os.path.abspath(preproc_dir)
    input_path = os.path.abspath(os.path.join(preproc_dir, "input.bin"))
    metadata_path = os.path.abspath(os.path.join(preproc_dir, "metadata.json"))

    if not os.path.isfile(input_path):
        raise FileNotFoundError(f"preproc input not found: {input_path}")
    if not os.path.isfile(metadata_path):
        raise FileNotFoundError(f"preproc metadata not found: {metadata_path}")

    with open(metadata_path, "r", encoding="utf-8") as fh:
        try:
            metadata = json.load(fh)
        except Exception as exc:  # pragma: no cover - defensive
            raise ValueError(f"failed to parse metadata.json: {exc}") from exc

    # Schema-version-aware validation: only validate if the metadata explicitly
    # declares `schema_version`. This allows existing producers that don't set
    # a version to continue to work (back-compat) while enabling strict
    # validation for newer producers.
    schema_version = metadata.get("schema_version")
    if schema_version:
        # Import validator helper (package import preferred, fallback to file)
        try:
            validator = importlib.import_module("auditor.detectors.static_detection.validator")
        except Exception:
            v_path = os.path.join(os.path.dirname(__file__), "validator.py")
            spec = importlib.util.spec_from_file_location("static_detection.validator", v_path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            validator = mod

        # Try versioned schema file first, then fallback to the unversioned schema
        schema_dir = os.path.join(os.path.dirname(__file__), "schemas")
        schema_candidates = [
            os.path.join(schema_dir, f"preproc.metadata.schema.{schema_version}.json"),
            os.path.join(schema_dir, "preproc.metadata.schema.json"),
        ]
        schema = None
        for sp in schema_candidates:
            if os.path.isfile(sp):
                with open(sp, "r", encoding="utf-8") as sfh:
                    schema = json.load(sfh)
                break

        if schema is None:
            raise RuntimeError(f"requested schema version {schema_version} but no matching schema file found")

        try:
            validator.validate_schema(metadata, schema)
        except RuntimeError:
            # Missing jsonschema dependency
            raise RuntimeError(
                "preproc schema validation requested but `jsonschema` is not installed; "
                "install `jsonschema` to enable strict checks"
            )
        except Exception as exc:
            raise ValueError(f"preproc metadata does not conform to schema: {exc}") from exc

    # Defensive: ensure input_path is inside the declared preproc_dir
    real_preproc = os.path.realpath(preproc_dir)
    real_input = os.path.realpath(input_path)
    if not (real_input == real_preproc or real_input.startswith(real_preproc + os.sep)):
        raise ValueError(f"preproc input.bin appears outside preproc_dir: {input_path}")

    computed_hash = _sha256_of_file(input_path)
    size = os.path.getsize(input_path)

    # If metadata contains a hash, ensure it matches computed
    meta_hash = metadata.get("file_hash") or metadata.get("sha256")
    if meta_hash and meta_hash != computed_hash:
        raise ValueError(
            f"preproc metadata file_hash mismatch: metadata={meta_hash} computed={computed_hash}"
        )

    file_hash = computed_hash

    preproc = Preproc(
        file_hash=file_hash,
        input_path=input_path,
        metadata_path=metadata_path,
        metadata=metadata,
        size=size,
    )

    return preproc
