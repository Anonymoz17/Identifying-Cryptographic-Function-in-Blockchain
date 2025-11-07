"""JSON schema validator helpers (skeleton).

This module wraps `jsonschema` when available; tests will mock or skip
schema validation as needed. Keep interfaces tiny.
"""
from typing import Any, Dict


def validate_schema(instance: Any, schema: Dict) -> None:
    """Validate `instance` against `schema`.

    The stub raises RuntimeError if schema package is missing. The real
    implementation should raise a descriptive `jsonschema.ValidationError`.
    """
    try:
        import jsonschema
    except Exception as exc:
        raise RuntimeError("jsonschema package is required for validation") from exc

    jsonschema.validate(instance=instance, schema=schema)


def quick_validate(instance: Any, schema_name: str) -> None:
    """Lightweight best-effort validation used when `jsonschema` is not
    available. This checks a few critical top-level keys depending on
    `schema_name` and raises ValueError on obvious violations.

    It's intentionally small — it's not a replacement for full schema
    validation, only a helpful guard to catch grossly malformed payloads.
    """
    if not isinstance(instance, dict):
        raise ValueError("instance must be a JSON object/dict")

    if schema_name == "hints":
        # ensure minimal required fields exist
        for k in ("schema_version", "timestamp", "hints"):
            if k not in instance:
                raise ValueError(f"hints payload missing required key: {k}")
        if not isinstance(instance.get("hints"), list):
            raise ValueError("hints must be an array")
    elif schema_name == "static_results":
        for k in ("schema_version", "timestamp", "findings"):
            if k not in instance:
                raise ValueError(f"static_results payload missing required key: {k}")
        if not isinstance(instance.get("findings"), list):
            raise ValueError("findings must be an array")
    else:
        # Generic sanity checks
        if "schema_version" not in instance:
            raise ValueError("payload missing schema_version")
