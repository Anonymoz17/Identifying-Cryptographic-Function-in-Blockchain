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
