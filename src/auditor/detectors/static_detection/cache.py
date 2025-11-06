"""Simple cache utilities (skeleton).

Will be extended with TTLs and invalidation. The stub provides a helper to
write a `.cache_meta.json` file recording generator versions.
"""
import json
import os
from typing import Dict, Optional, Tuple
from datetime import datetime, timezone


DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60  # 7 days


def write_cache_meta(out_dir: str, meta: Dict) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, ".cache_meta.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh)
    return path


def read_cache_meta(out_dir: str) -> Optional[Dict]:
    path = os.path.join(out_dir, ".cache_meta.json")
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _parse_iso_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        # ISO format with timezone produced by datetime.now(timezone.utc).isoformat()
        return datetime.fromisoformat(ts)
    except Exception:
        try:
            # fallback: strip trailing Z
            if ts.endswith("Z"):
                return datetime.fromisoformat(ts[:-1])
        except Exception:
            return None


def is_cache_fresh(cache_meta: Dict, max_age_seconds: int = DEFAULT_TTL_SECONDS) -> bool:
    ts = _parse_iso_ts(cache_meta.get("generated_at"))
    if not ts:
        return False
    age = (datetime.now(timezone.utc) - ts).total_seconds()
    return age <= max_age_seconds


def _tool_versions_equal(a: Optional[Dict], b: Optional[Dict]) -> bool:
    """Relaxed tool version compatibility:

    - If neither side provides versions, they're compatible.
    - If one side omits a tool version entirely, ignore that tool (treat as compatible).
    - If both sides provide a value for a given tool, compare only the major
      version (the component before the first dot). Empty or None values are
      ignored.
    """
    if not a and not b:
        return True
    if not a or not b:
        # If one side doesn't provide any tool versions, treat as compatible.
        return True

    for tool, ver_a in (a or {}).items():
        ver_b = (b or {}).get(tool)
        if ver_a is None or ver_b is None:
            # missing value on either side -> ignore this tool
            continue
        sa = str(ver_a).strip()
        sb = str(ver_b).strip()
        if not sa or not sb:
            continue
        # compare major version only
        major_a = sa.split(".")[0]
        major_b = sb.split(".")[0]
        if major_a != major_b:
            return False

    # Also check any tools present in b but not in a (the symmetric case)
    for tool, ver_b in (b or {}).items():
        if tool in (a or {}):
            continue
        ver_a = (a or {}).get(tool)
        if ver_a is None or ver_b is None:
            continue
        sa = str(ver_a).strip()
        sb = str(ver_b).strip()
        if not sa or not sb:
            continue
        if sa.split(".")[0] != sb.split(".")[0]:
            return False

    return True


def is_cache_compatible(cache_meta: Dict, ctx, require_profile_match: bool = True) -> Tuple[bool, str]:
    # profile check
    if require_profile_match:
        if cache_meta.get("profile") != getattr(ctx, "profile", None):
            return False, "profile_mismatch"

    cache_tool_versions = cache_meta.get("tool_versions") or {}
    ctx_tool_versions = {}
    tv = getattr(ctx, "tool_versions", None)
    if hasattr(tv, "__dict__"):
        ctx_tool_versions = tv.__dict__
    elif isinstance(tv, dict):
        ctx_tool_versions = tv

    if not _tool_versions_equal(cache_tool_versions, ctx_tool_versions):
        return False, "tool_versions_mismatch"

    return True, "ok"


def should_use_cache(analysis_dir: str, ctx, max_age_seconds: int = DEFAULT_TTL_SECONDS) -> Tuple[bool, str]:
    """Decide whether cached static results in analysis_dir can be reused.

    Returns (use_cache: bool, reason: str).
    """
    if getattr(ctx, "force", False):
        return False, "force_requested"

    static_results_path = os.path.join(analysis_dir, "static_results.json")
    if not os.path.isfile(static_results_path):
        return False, "no_static_results"

    cache_meta = read_cache_meta(analysis_dir)
    if not cache_meta:
        return False, "no_cache_meta"

    # freshness
    if not is_cache_fresh(cache_meta, max_age_seconds=max_age_seconds):
        return False, "stale"

    # compatibility
    ok, reason = is_cache_compatible(cache_meta, ctx)
    if not ok:
        return False, reason

    return True, "ok"
