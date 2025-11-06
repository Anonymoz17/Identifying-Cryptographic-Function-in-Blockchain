"""Package static results and write `static_results.json`.

Validate the packaged payload against `schemas/static_results.schema.json` if
available. If `jsonschema` isn't installed the validator raises RuntimeError and
we write the file but annotate the `meta` field accordingly.
"""
from typing import Dict, Any
import json
import os
from datetime import datetime, timezone

from . import validator


def package_results(file_hash: str, findings: Any, out_dir: str, meta: Dict = None) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "static_results.json")

    payload = {
        "file_hash": file_hash,
        "schema_version": "0.0.1",
    "timestamp": datetime.now(timezone.utc).isoformat(),
        "findings": findings,
        "meta": meta or {},
    }

    # Try schema validation
    schema_path = os.path.join(os.path.dirname(__file__), "schemas", "static_results.schema.json")
    if os.path.isfile(schema_path):
        try:
            with open(schema_path, "r", encoding="utf-8") as sfh:
                schema = json.load(sfh)
            try:
                validator.validate_schema(payload, schema)
            except RuntimeError:
                payload.setdefault("meta", {})["schema_validation"] = "skipped: jsonschema not installed"
        except Exception:
            payload.setdefault("meta", {})["schema_validation"] = "skipped: schema load error"

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    return path
