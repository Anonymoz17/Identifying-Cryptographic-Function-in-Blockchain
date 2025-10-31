"""Policy baseline validator helpers.

Expose a small function usable by the UI and tests to validate a JSON text
against the `schemas/policy.baseline.schema.json`. Uses `jsonschema` if
available; otherwise does a best-effort structural check (requires `version`).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Tuple

try:
    import jsonschema  # type: ignore

    _HAS_JSONSCHEMA = True
except Exception:
    jsonschema = None  # type: ignore
    _HAS_JSONSCHEMA = False


_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "schemas" / "policy.baseline.schema.json"
)


def _load_schema() -> dict:
    try:
        with _SCHEMA_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


_schema_cache = None


def validate_policy_text(txt: str) -> Tuple[bool, List[str]]:
    """Validate policy JSON text.

    Returns (valid, errors). If valid is True, errors==[].
    """
    global _schema_cache
    try:
        obj = json.loads(txt)
    except Exception as e:
        return False, [f"JSON parse error: {e}"]

    if _HAS_JSONSCHEMA:
        if _schema_cache is None:
            _schema_cache = _load_schema()
        try:
            # collect all errors for user-friendly display
            validator = jsonschema.Draft7Validator(_schema_cache)
            errors = []
            for err in sorted(validator.iter_errors(obj), key=lambda e: e.path):
                loc = "/".join(str(p) for p in err.absolute_path) or "(root)"
                errors.append(f"{loc}: {err.message}")
            if errors:
                return False, errors
            return True, []
        except Exception as e:
            # schema loading/validation failure -> return parseable error
            return False, [f"Schema validation failure: {e}"]
    # fallback minimal checks
    if not isinstance(obj, dict):
        return False, ["Top-level JSON must be an object"]
    # accept either a top-level 'version' or a version inside 'metadata'
    has_version = "version" in obj or (
        isinstance(obj.get("metadata"), dict) and "version" in obj.get("metadata")
    )
    if not has_version:
        return False, [
            "Missing required 'version' field (top-level or metadata.version)"
        ]
    if not any(k in obj for k in ("whitelist", "rules", "scoring")):
        return False, [
            "Must contain at least one of 'whitelist', 'rules', or 'scoring'"
        ]
    return True, []
