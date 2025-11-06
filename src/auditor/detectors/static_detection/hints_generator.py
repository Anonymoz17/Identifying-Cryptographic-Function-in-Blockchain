"""Create `hints.json` and redacted `hints_public.json`.

This module writes a structured hints payload and validates it against the
`schemas/hints.schema.json` if available. If jsonschema is not installed the
validator will raise a RuntimeError; in that case we write the file but include
an entry in the payload meta indicating validation was skipped.
"""
from typing import Dict, List, Optional
import json
import os
from datetime import datetime, timezone

from . import validator


def _redact_hint(h: Dict) -> Dict:
    h2 = dict(h)
    # Remove fields considered sensitive for public exposure
    for k in ("address_or_range", "evidence_snippet", "call_graph_neighbors", "raw_bytes", "evidence"):
        if k in h2:
            h2.pop(k, None)
    # Also avoid exposing large blobs or internal-only keys
    for k in list(h2.keys()):
        if k.startswith("_internal_"):
            h2.pop(k, None)
    return h2


def generate_hints(findings: List[Dict], out_dir: str, redact: bool = False, file_hash: Optional[str] = "") -> str:
    """Write hints JSON to out_dir and return the path.

    Args:
        findings: list of finding dicts
        out_dir: directory to write file to
        redact: if True produce a public redacted hints file
        file_hash: optional SHA256 file hash to include in payload
    """
    os.makedirs(out_dir, exist_ok=True)
    file_name = "hints_public.json" if redact else "hints.json"
    path = os.path.join(out_dir, file_name)

    # Prepare payload
    timestamp = datetime.now(timezone.utc).isoformat()
    # Normalize findings into hints items that conform to the hints schema.
    hints = []
    for f in findings:
        # prefer score, fallback to confidence
        confidence = None
        if isinstance(f.get("score"), (int, float)):
            confidence = float(f.get("score"))
        elif isinstance(f.get("confidence"), (int, float)):
            confidence = float(f.get("confidence"))
        else:
            # try nested evidence snippet as weak signal
            confidence = 0.0

        hint = {
            "id": f.get("id") or f.get("uid") or f"hint-{hash(str(f))[:8]}",
            "type": f.get("type", "unknown"),
            "name": f.get("name"),
            "confidence": confidence,
            "reason_tags": f.get("reason_tags", []),
        }

        # include optional fields when available
        if "address_or_range" in f:
            hint["address_or_range"] = f["address_or_range"]
        if "call_graph_neighbors" in f:
            hint["call_graph_neighbors"] = f["call_graph_neighbors"]
        # prefer explicit evidence_snippet, otherwise try evidence.snippet
        if "evidence_snippet" in f:
            hint["evidence_snippet"] = f["evidence_snippet"]
        elif isinstance(f.get("evidence"), dict) and f["evidence"].get("snippet"):
            hint["evidence_snippet"] = f["evidence"]["snippet"]

        hints.append(hint)

    payload = {
        "file_hash": file_hash or "",
        "schema_version": "1.0",
        "timestamp": timestamp,
        "language": "unknown",
        "hints": hints,
    }

    # Try to validate against schema if available
    schema_path = os.path.join(os.path.dirname(__file__), "schemas", "hints.schema.json")
    if os.path.isfile(schema_path):
        try:
            with open(schema_path, "r", encoding="utf-8") as sfh:
                schema = json.load(sfh)
            try:
                validator.validate_schema(payload, schema)
            except RuntimeError:
                # jsonschema missing — proceed but annotate payload meta by writing a companion file
                payload.setdefault("meta", {})["schema_validation"] = "skipped: jsonschema not installed"
        except Exception:
            # If schema is malformed or unavailable, proceed but annotate
            payload.setdefault("meta", {})["schema_validation"] = "skipped: schema load error"

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)

    # If this was a full hints file (not a requested redacted write), also
    # produce a public redacted variant that removes sensitive fields.
    if not redact:
        pub_path = os.path.join(out_dir, "hints_public.json")
        redacted_hints = [_redact_hint(h) for h in hints]
        pub_payload = {
            "file_hash": file_hash or "",
            "schema_version": "1.0",
            "timestamp": timestamp,
            "language": "unknown",
            "hints": redacted_hints,
            "redacted": True,
        }

        # Try to validate public payload using same schema if available
        if os.path.isfile(schema_path):
            try:
                validator.validate_schema(pub_payload, schema)
            except RuntimeError:
                pub_payload.setdefault("meta", {})["schema_validation"] = "skipped: jsonschema not installed"
            except Exception:
                pub_payload.setdefault("meta", {})["schema_validation"] = "skipped: public schema validation error"

        with open(pub_path, "w", encoding="utf-8") as fh:
            json.dump(pub_payload, fh, indent=2)

    return path
