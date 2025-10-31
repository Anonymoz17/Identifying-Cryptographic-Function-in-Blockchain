from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Tuple

from auditor.auditlog import AuditLog
from auditor.case import Engagement
from policy_validator import validate_policy_text


def import_and_record_policy(
    eng: Engagement, policy_path: str, auditlog_path: str
) -> Tuple[bool, str]:
    """Validate a policy file, import into the engagement, and record an audit event.

    Returns (True, dest_path) on success, or (False, error_message) on failure.
    """
    p = Path(policy_path)
    al = AuditLog(auditlog_path)

    if not p.exists():
        al.append(
            "engagement.policy_import_failed",
            {"source": str(policy_path), "error": "file_not_found"},
        )
        return False, "file_not_found"

    try:
        txt = p.read_text(encoding="utf-8")
    except Exception as e:
        al.append(
            "engagement.policy_import_failed",
            {"source": str(policy_path), "error": f"read_error: {e}"},
        )
        return False, f"read_error: {e}"

    # attempt to parse JSON and normalize if needed so it validates
    try:
        obj = json.loads(txt)
    except Exception as e:
        al.append(
            "engagement.policy_import_failed",
            {"source": str(policy_path), "errors": [f"JSON parse error: {e}"]},
        )
        return False, f"JSON parse error: {e}"

    # If the policy uses metadata.version instead of a top-level 'version'
    # synthesize a temporary normalized JSON for validation only so we accept
    # both styles entered by users.
    txt_for_validation = txt
    if (
        "version" not in obj
        and isinstance(obj.get("metadata"), dict)
        and "version" in obj.get("metadata")
    ):
        tmp = dict(obj)
        tmp["version"] = obj["metadata"]["version"]
        try:
            txt_for_validation = json.dumps(tmp, sort_keys=True, ensure_ascii=False)
        except Exception:
            txt_for_validation = txt

    # validate JSON and schema
    valid, errors = validate_policy_text(txt_for_validation)
    if not valid:
        al.append(
            "engagement.policy_import_failed",
            {"source": str(policy_path), "errors": errors},
        )
        return False, "; ".join(errors)

    # import via Engagement helper (makes immutable copy and writes .sha256 sidecar)
    try:
        dest = eng.import_policy_baseline(str(policy_path))
    except Exception as e:
        al.append(
            "engagement.policy_import_failed",
            {"source": str(policy_path), "error": f"import_error: {e}"},
        )
        return False, f"import_error: {e}"

    # read or compute sha
    dest_path = Path(dest)
    sidecar = dest_path.with_suffix(dest_path.suffix + ".sha256")
    if sidecar.exists():
        sha = sidecar.read_text(encoding="utf-8").strip()
    else:
        # fallback: compute from the copied file
        try:
            data = dest_path.read_bytes()
            sha = hashlib.sha256(data).hexdigest()
            try:
                sidecar.write_text(sha, encoding="utf-8")
            except Exception:
                pass
        except Exception:
            sha = ""

    # try to extract schema/version from policy if present
    try:
        obj = json.loads(txt)
        version = obj.get("metadata", {}).get("version")
    except Exception:
        version = None

    al.append(
        "engagement.policy_imported",
        {
            "source": str(policy_path),
            "dest": str(dest),
            "sha256": sha,
            "schema_version": version,
        },
    )

    return True, str(dest)
