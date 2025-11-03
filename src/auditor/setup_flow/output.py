"""Safe output storage helpers for the setup pipeline.

This module provides small, well-tested helpers to create a clean output
folder per preprocessed artifact and to write text/binary artifacts there in
an atomic, sanitized and permission-minded way.

APIs:
 - sanitize_name(name) -> str
 - make_output_dir(ctx, sha, subdir='outputs') -> Path
 - write_text_artifact(ctx, sha, name, text, encoding='utf-8', notifier=None)
 - write_binary_artifact(ctx, sha, name, data, notifier=None)
 - copy_to_output(ctx, sha, src_path, name=None, notifier=None)

These helpers intentionally keep behavior narrow (no archive logic). They
should be used by preprocessing stages that need to persist derived files
or extracted code/text safely next to the `preproc/<sha>/` artifact folder.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
from pathlib import Path
from typing import Optional
from typing import Union
import platform

from .setupcontext import SetupContext
from .setupmessages import Notifier
from .persistence import atomic_write_json


_SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")


def sanitize_name(name: str, max_len: int = 200) -> str:
    """Return a filesystem-safe short name derived from `name`.

    Replaces unsafe characters with underscores and trims length. Does not
    attempt to be cryptographically unique: callers should include the sha if
    uniqueness is required.
    """
    if not name:
        return "unnamed"
    n = _SAFE_NAME_RE.sub("_", name)
    n = n.strip("._-")
    if len(n) > max_len:
        n = n[:max_len]
    if not n:
        return "unnamed"
    return n


def _ensure_dir(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, mode)
    except Exception:
        # best-effort on Windows/limited perms
        pass


def make_output_dir(ctx: SetupContext, sha: str, subdir: str = "outputs") -> Path:
    """Create and return an artifact-scoped output directory: preproc/<sha>/<subdir>/.

    Uses `ctx.case_dir` if present, otherwise falls back to `ctx.workdir`.
    """
    base = Path(ctx.case_dir) if getattr(ctx, "case_dir", None) else Path(ctx.workdir)
    art_dir = base / "preproc" / sha / subdir
    _ensure_dir(art_dir)
    return art_dir


def _atomic_write_bytes(path: Path, data: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.parent.mkdir(parents=True, exist_ok=True)
    with tmp.open("wb") as fh:
        fh.write(data)
        try:
            fh.flush()
            os.fsync(fh.fileno())
        except Exception:
            pass
    try:
        tmp.replace(path)
    except Exception:
        tmp.rename(path)


def write_text_artifact(ctx: SetupContext, sha: str, name: str, text: str, encoding: str = "utf-8", notifier: Optional[Notifier] = None) -> Path:
    """Write a small text artifact into the artifact outputs folder atomically.

    Returns the final Path.
    """
    safe = sanitize_name(name)
    out_dir = make_output_dir(ctx, sha)
    dest = out_dir / safe
    _atomic_write_bytes(dest, text.encode(encoding))
    try:
        os.chmod(dest, 0o600)
    except Exception:
        pass
    if notifier:
        try:
            notifier.info("wrote output", path=str(dest))
        except Exception:
            pass
    return dest


def write_binary_artifact(ctx: SetupContext, sha: str, name: str, data: bytes, notifier: Optional[Notifier] = None) -> Path:
    """Write binary data into the artifact outputs folder atomically.

    Returns the final Path.
    """
    safe = sanitize_name(name)
    out_dir = make_output_dir(ctx, sha)
    dest = out_dir / safe
    _atomic_write_bytes(dest, data)
    try:
        os.chmod(dest, 0o600)
    except Exception:
        pass
    if notifier:
        try:
            notifier.info("wrote binary output", path=str(dest))
        except Exception:
            pass
    return dest


def copy_to_output(ctx: SetupContext, sha: str, src: Path, name: Optional[str] = None, notifier: Optional[Notifier] = None) -> Optional[Path]:
    """Copy an existing file into the artifact outputs folder with a safe name.

    If `name` is not provided the source filename (sanitized) is used. Returns
    the destination path or None on error.
    """
    try:
        if not src.exists() or not src.is_file():
            return None
        out_dir = make_output_dir(ctx, sha)
        safe = sanitize_name(name or src.name)
        dest = out_dir / safe
        # copy via temp then replace to be atomic
        tmp = dest.with_suffix(dest.suffix + ".tmp")
        shutil.copy2(str(src), str(tmp))
        try:
            tmp.replace(dest)
        except Exception:
            tmp.rename(dest)
        try:
            os.chmod(dest, 0o600)
        except Exception:
            pass
        if notifier:
            try:
                notifier.info("copied output", path=str(dest))
            except Exception:
                pass
        return dest
    except Exception:
        return None


def get_default_workdir(app_name: str = "CryptoScope", case_subdir: str = "cases") -> Path:
    """Return a sensible OS-specific default workdir for the application.

    On Windows this uses %LOCALAPPDATA%/<app_name>/<case_subdir>, on macOS
    it uses ~/Library/Application Support/<app_name>/<case_subdir> and on
    Linux it prefers $XDG_DATA_HOME/<app_name>/<case_subdir> or
    ~/.local/share/<app_name>/<case_subdir>.

    The directory is created (best-effort) and returned as a Path.
    """
    sys = platform.system().lower()
    try:
        if sys.startswith("win"):
            local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
            base = Path(local) / app_name
        elif sys.startswith("darwin"):
            base = Path.home() / "Library" / "Application Support" / app_name
        else:
            base = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share")) / app_name
        dest = base / case_subdir
        _ensure_dir(dest)
        return dest
    except Exception:
        # fallback to a local folder inside the cwd or home
        try:
            fallback = Path.cwd() / app_name / case_subdir
            _ensure_dir(fallback)
            return fallback
        except Exception:
            return Path.home()


def is_within_default(path: Union[str, Path], app_name: str = "CryptoScope", case_subdir: str = "cases") -> bool:
    """Return True if `path` is inside the default workdir for the app.

    This is a best-effort check used by the UI to recommend the canonical path.
    """
    try:
        p = Path(path).resolve()
        d = get_default_workdir(app_name=app_name, case_subdir=case_subdir).resolve()
        return p == d or d in p.parents
    except Exception:
        return False
