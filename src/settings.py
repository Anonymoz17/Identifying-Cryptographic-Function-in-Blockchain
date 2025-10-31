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
