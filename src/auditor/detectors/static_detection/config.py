"""Simple persistent config helpers for the static-detection subsystem.

Stores a small JSON config under the user's config directory (or %APPDATA%
on Windows). This is intentionally minimal: only `ghidra.install_dir` is
needed by the detection flow today.
"""
from pathlib import Path
import json
import os
from typing import Dict, Any, Optional


def _default_config_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "cryptoscope" / "config.json"


def load_config(path: Optional[Path] = None) -> Dict[str, Any]:
    p = path or _default_config_path()
    try:
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        # best-effort: return empty on any error
        pass
    return {}


def save_config(cfg: Dict[str, Any], path: Optional[Path] = None) -> None:
    p = path or _default_config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(cfg, indent=2), encoding="utf-8")


def get_ghidra_install_dir(path: Optional[Path] = None) -> Optional[str]:
    cfg = load_config(path)
    gh = cfg.get("ghidra", {}) if isinstance(cfg, dict) else {}
    return gh.get("install_dir")


def set_ghidra_install_dir(install_dir: str, path: Optional[Path] = None) -> None:
    cfg = load_config(path)
    if not isinstance(cfg, dict):
        cfg = {}
    gh = cfg.get("ghidra") if isinstance(cfg.get("ghidra"), dict) else {}
    gh["install_dir"] = install_dir
    cfg["ghidra"] = gh
    save_config(cfg, path)


def get_ghidra_run_policy(path: Optional[Path] = None) -> str:
    """Get the Ghidra execution policy: 'auto' (default), 'always', or 'never'.
    
    - 'auto': Use intelligent filtering (skip source code, run on binaries)
    - 'always': Force Ghidra on all files (slow but comprehensive)
    - 'never': Skip Ghidra entirely (fast but may miss binary-only patterns)
    """
    cfg = load_config(path)
    gh = cfg.get("ghidra", {}) if isinstance(cfg, dict) else {}
    return gh.get("run_policy", "auto")


def set_ghidra_run_policy(policy: str, path: Optional[Path] = None) -> None:
    """Set the Ghidra execution policy.
    
    Args:
        policy: One of 'auto', 'always', or 'never'
    """
    if policy not in ("auto", "always", "never"):
        raise ValueError(f"Invalid policy: {policy}. Must be 'auto', 'always', or 'never'")
    
    cfg = load_config(path)
    if not isinstance(cfg, dict):
        cfg = {}
    gh = cfg.get("ghidra") if isinstance(cfg.get("ghidra"), dict) else {}
    gh["run_policy"] = policy
    cfg["ghidra"] = gh
    save_config(cfg, path)
