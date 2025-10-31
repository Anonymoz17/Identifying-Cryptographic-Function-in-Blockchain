"""Simple cross-platform settings storage for the app.

Stores a small JSON settings file in a per-user application data location
and exposes helpers to load/save settings and compute a canonical default
workdir for case storage.

The implementation avoids external dependencies and uses an atomic
replace when writing. On POSIX systems the settings directory and file
are created with restrictive permissions where possible.
"""

from __future__ import annotations

import json
import os
import platform
from pathlib import Path
from typing import Any, Dict, Optional

_APP_NAME = "CryptoScope"
_SETTINGS_FILE = "settings.json"


def _get_user_data_dir() -> Path:
    """Return a platform-appropriate per-user data directory for the app."""
    system = platform.system()
    home = Path.home()
    if system == "Windows":
        appdata = os.getenv("APPDATA")
        if appdata:
            return Path(appdata) / _APP_NAME
        return home / f".{_APP_NAME}"
    if system == "Darwin":
        return home / "Library" / "Application Support" / _APP_NAME
    # Linux / other: honor XDG_DATA_HOME if set
    xdg = os.getenv("XDG_DATA_HOME")
    if xdg:
        return Path(xdg) / _APP_NAME
    return home / ".local" / "share" / _APP_NAME


def ensure_settings_dir() -> Path:
    d = _get_user_data_dir()
    d.mkdir(parents=True, exist_ok=True)
    # try to restrict permissions on POSIX systems
    try:
        if os.name == "posix":
            d.chmod(0o700)
    except Exception:
        pass
    return d


def settings_path() -> Path:
    return ensure_settings_dir() / _SETTINGS_FILE


def load_settings() -> Dict[str, Any]:
    p = settings_path()
    if not p.exists():
        return {}
    try:
        with p.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_settings(data: Dict[str, Any]) -> None:
    p = settings_path()
    # atomic write: write to temp then replace
    tmp = p.with_suffix(".tmp")
    try:
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        try:
            if os.name == "posix":
                tmp.chmod(0o600)
        except Exception:
            pass
        os.replace(str(tmp), str(p))
    finally:
        if tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass


def get_setting(key: str, default: Optional[Any] = None) -> Any:
    s = load_settings()
    return s.get(key, default)


def set_setting(key: str, value: Any) -> None:
    s = load_settings()
    s[key] = value
    save_settings(s)


def get_default_workdir() -> Path:
    """Return a canonical default workdir to use for cases.

    Order of preference:
    - user setting saved under settings.json (key: 'workdir')
    - platform app-data <app>/cases
    - fallback to home/CryptoScope/cases
    """
    val = get_setting("workdir")
    if val:
        try:
            return Path(val).expanduser().resolve()
        except Exception:
            pass

    data_dir = _get_user_data_dir()
    try:
        base = Path(data_dir) / "cases"
        base.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            try:
                base.chmod(0o700)
            except Exception:
                pass
        return base.resolve()
    except Exception:
        # final fallback
        fallback = Path.home() / _APP_NAME / "cases"
        try:
            fallback.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return fallback.resolve()


def set_default_workdir(path: str) -> None:
    """Persist the user's preferred workdir into settings.

    This function stores the absolute resolved path in the settings file.
    """
    if not path:
        return
    try:
        p = Path(path).expanduser().resolve()
        set_setting("workdir", str(p))
    except Exception:
        # best-effort: store raw string
        set_setting("workdir", path)


def get_canonical_workdir() -> Path:
    """Return the platform-canonical workdir (ignores user override).

    This is useful for UI guidance to show the recommended location where
    cases will be stored by default (e.g., <appdata>/CryptoScope/cases).
    """
    data_dir = _get_user_data_dir()
    try:
        base = Path(data_dir) / "cases"
        base.mkdir(parents=True, exist_ok=True)
        return base.resolve()
    except Exception:
        fallback = Path.home() / _APP_NAME / "cases"
        try:
            fallback.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass
        return fallback.resolve()


def reset_default_workdir() -> None:
    """Remove any user-specified workdir from settings so the canonical
    default will be used on next call to `get_default_workdir()`.
    """
    s = load_settings()
    if "workdir" in s:
        try:
            del s["workdir"]
            save_settings(s)
        except Exception:
            # best-effort: rewrite without the key
            try:
                s2 = {k: v for k, v in s.items() if k != "workdir"}
                save_settings(s2)
            except Exception:
                pass


def get_fast_count_timeout() -> float:
    """Return the fast-count timeout in seconds (float).

    This controls how long the fast input counting routine should run before
    giving up and returning None. The default is 0.8 seconds which is a
    reasonable balance between speed and accuracy on typical machines.
    """
    val = get_setting("fast_count_timeout")
    try:
        if val is None:
            return 0.8
        return float(val)
    except Exception:
        return 0.8


def set_fast_count_timeout(seconds: float) -> None:
    """Persist the fast-count timeout (in seconds) into settings."""
    try:
        secs = float(seconds)
    except Exception:
        # ignore invalid values
        return
    # clamp to a sensible range (0.0 allowed to disable fast counting)
    if secs < 0:
        secs = 0.0
    set_setting("fast_count_timeout", secs)
