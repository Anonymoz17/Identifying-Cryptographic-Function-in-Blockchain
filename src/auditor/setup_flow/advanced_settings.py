from __future__ import annotations

from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from .output import get_default_workdir
import os
import platform
from .persistence import atomic_write_json


def profiles_dir(app_name: str = "CryptoScope") -> Path:
    """Return a profiles directory that lives alongside the case subdir (not under it).

    This computes the application base path and stores profiles under <app_base>/profiles
    so profiles are siblings of the per-case subdir rather than children of it.
    """
    try:
        # compute base without creating the case_subdir side-effect
        sys = platform.system().lower()
        if sys.startswith("win"):
            local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
            base = Path(local) / app_name
        elif sys.startswith("darwin"):
            base = Path.home() / "Library" / "Application Support" / app_name
        else:
            base = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")) / app_name
        d = base / "profiles"
        d.mkdir(parents=True, exist_ok=True)
        return d
    except Exception:
        # fallback to existing behaviour if anything goes wrong
        d = get_default_workdir(app_name=app_name) / "profiles"
        d.mkdir(parents=True, exist_ok=True)
        return d


def profile_path(name: str = "default", app_name: str = "CryptoScope") -> Path:
    p = profiles_dir(app_name=app_name) / f"{name}.json"
    return p


def save_profile(data: Dict[str, Any], name: str = "default", app_name: str = "CryptoScope") -> Path:
    """Atomically save a profile dict to the profiles directory. Returns path."""
    p = profile_path(name=name, app_name=app_name)
    atomic_write_json(p, data)
    return p


def load_profile(name: str = "default", app_name: str = "CryptoScope") -> Optional[Dict[str, Any]]:
    p = profile_path(name=name, app_name=app_name)
    if not p.exists():
        return None
    try:
        import json

        with p.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def list_profiles(app_name: str = "CryptoScope") -> List[str]:
    d = profiles_dir(app_name=app_name)
    out: List[str] = []
    try:
        for f in d.glob("*.json"):
            if f.is_file():
                out.append(f.stem)
    except Exception:
        pass
    return out


def default_workdir_preview(case_subdir: str = "cases", app_name: str = "CryptoScope") -> str:
    """Return the canonical default workdir path for preview WITHOUT creating directories.

    This avoids creating folders during live UI previews as the user types a case
    subdirectory. The returned string is the path that would be used by
    `get_default_workdir(app_name, case_subdir)` but the function is side-effect free.
    """
    try:
        sys = platform.system().lower()
        if sys.startswith("win"):
            local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
            base = Path(local) / app_name
        elif sys.startswith("darwin"):
            base = Path.home() / "Library" / "Application Support" / app_name
        else:
            base = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")) / app_name
        return str(base / case_subdir)
    except Exception:
        try:
            return str(get_default_workdir(app_name=app_name, case_subdir=case_subdir))
        except Exception:
            return str(get_default_workdir(app_name=app_name))


def validate_policy_path(path: str) -> Tuple[bool, str]:
    """Validate that a policy baseline path exists, is readable, and looks like a policy JSON.

    Returns (True, '') on success, or (False, message) on failure.
    The structural check is heuristic: the JSON must be an object and contain at least
    one recognisable top-level policy key (e.g. 'rules','policy','allow','deny','version').
    """
    if not path:
        return True, ""
    try:
        p = Path(path)
        if not (p.exists() and p.is_file()):
            return False, "Policy file not found"
        try:
            text = p.read_text(encoding="utf-8")
        except Exception:
            return False, "Policy file unreadable"
        try:
            import json

            obj = json.loads(text)
        except Exception as e:
            return False, f"Invalid JSON: {e}"
        # structural heuristics
        if not isinstance(obj, dict):
            return False, "Policy JSON must be an object"
        expected_keys = {"rules", "policy", "allow", "deny", "version", "settings", "policies", "baseline"}
        if not (expected_keys & set(obj.keys())):
            return False, "JSON does not look like a policy baseline (missing expected keys)"
        return True, ""
    except Exception as e:
        return False, f"Policy validation error: {e}"
