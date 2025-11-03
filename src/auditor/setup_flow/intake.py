from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, Iterator, Optional, Set

from .setupcontext import SetupContext
from .setupmessages import Notifier


DEFAULT_EXCLUDE_DIRS: Set[str] = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "build",
    "dist",
    ".pytest_cache",
    ".idea",
    ".vscode",
    "target",
    "cmake-build-debug",
    ".github",
}


DEFAULT_ALLOWED_EXTS = {
    # smart contract languages
    ".sol",
    ".vy",
    # common code
    ".py",
    ".js",
    ".ts",
    ".go",
    ".rs",
    ".c",
    ".cpp",
    ".h",
    ".hpp",
    ".java",
    ".kt",
    ".cs",
    # low-level / assembly, WASM
    ".s",
    ".S",
    ".asm",
    ".wat",
    ".wasm",
    # configs / manifests often useful
    ".json",
    ".yaml",
    ".yml",
    ".toml",
}


DEFAULT_DENY_BIN_EXTS = {
    ".so",
    ".dll",
    ".dylib",
    ".exe",
    ".o",
    ".obj",
    ".a",
    ".lib",
    ".class",
    ".jar",
    ".pyc",
    ".pyo",
    ".rlib",
}


def _is_likely_binary(path: Path, read_bytes: int = 4096, nontext_threshold: float = 0.30) -> bool:
    """Heuristic: read up to `read_bytes` and return True if content looks binary.

    Criteria:
    - Contains a NUL byte (very likely binary), or
    - Fraction of non-printable bytes > nontext_threshold
    """
    try:
        with path.open("rb") as fh:
            data = fh.read(read_bytes)
            if not data:
                return False
            if b"\x00" in data:
                return True
            # count non-text bytes
            nontext = 0
            for b in data:
                # allow tab(9), LF(10), CR(13), and printable ASCII 32-126
                if b in (9, 10, 13):
                    continue
                if 32 <= b <= 126:
                    continue
                nontext += 1
            return (nontext / len(data)) > nontext_threshold
    except Exception:
        # if we can't read, be conservative and treat as binary
        return True


def _is_within_root(resolved: Path, root: Path) -> bool:
    try:
        resolved.relative_to(root)
        return True
    except Exception:
        return False


def safe_enumerate(
    ctx: SetupContext,
    notifier: Optional[Notifier] = None,
    max_files: Optional[int] = None,
) -> Iterator[Dict]:
    """Yield file metadata dicts for files inside ctx.scope.

    Each yielded item is a dict:
      { 'path': Path, 'relpath': Path (relative to scope), 'size': int }

    The function applies exclusion rules, symlink/traversal safety checks and
    file-size / extension filters. It emits Notifier messages for each file:
    OK for yielded files, SKIP for excluded ones, WARN for suspicious entries.
    """
    if notifier is None:
        notifier = Notifier()

    scope: Path = Path(ctx.scope)
    if not scope.is_dir():
        notifier.warn("Cannot enumerate: scope is not a directory", path=str(scope))
        return

    exclude_dirs = set(ctx.config.exclude_dirs) if getattr(ctx.config, "exclude_dirs", None) else set()
    exclude_dirs |= DEFAULT_EXCLUDE_DIRS

    allowed_exts = None
    if getattr(ctx.config, "allowed_exts", None):
        allowed_exts = set(e.lower() for e in ctx.config.allowed_exts)
    else:
        allowed_exts = DEFAULT_ALLOWED_EXTS

    max_file_size = max_files if max_files is not None else ctx.config.max_file_size
    file_count = 0

    # Walk directory tree safely using os.walk (no followlinks)
    for root, dirs, files in os.walk(scope, topdown=True, followlinks=False):
        # prune excluded directories in-place
        dirs[:] = [d for d in dirs if d not in exclude_dirs]

        # enforce resource limits
        if max_files is not None and file_count >= max_files:
            notifier.warn("File enumeration limit reached", details={"max_files": max_files})
            break

        for name in files:
            fpath = Path(root) / name

            # prevent traversal/symlink escape: resolve target and ensure it's inside scope
            try:
                if fpath.is_symlink():
                    target = fpath.resolve()
                    if not _is_within_root(target, scope):
                        notifier.warn("Symlink points outside scope; skipping", path=str(fpath), details={"target": str(target)})
                        notifier.skip("Symlink outside scope", path=str(fpath))
                        continue
                else:
                    resolved = fpath.resolve()
                    if not _is_within_root(resolved, scope):
                        notifier.warn("Resolved path outside scope; skipping", path=str(fpath), details={"resolved": str(resolved)})
                        notifier.skip("Resolved path outside scope", path=str(fpath))
                        continue
            except Exception as e:
                notifier.warn("Error resolving path; skipping", path=str(fpath), details={"error": str(e)})
                continue

            # file size filter
            try:
                size = fpath.stat().st_size
            except Exception as e:
                notifier.warn("Could not stat file; skipping", path=str(fpath), details={"error": str(e)})
                continue

            if max_file_size is not None and size > max_file_size:
                notifier.skip("File too large", path=str(fpath), details={"size": size, "max": max_file_size})
                continue

            # extension filtering and binary checks
            ext = fpath.suffix.lower()

            # deny-list for prebuilt binary libraries unless explicitly allowed
            if ext in DEFAULT_DENY_BIN_EXTS and not getattr(ctx.config, "allow_binary_libs", False):
                notifier.skip("Binary library excluded", path=str(fpath), details={"ext": ext})
                continue

            if allowed_exts and ext not in allowed_exts:
                # If extension not allowed, check if file is obviously text; if binary, skip.
                if _is_likely_binary(fpath):
                    notifier.skip("Binary file (unknown ext) excluded", path=str(fpath), details={"ext": ext})
                    continue
                else:
                    notifier.skip("Extension not in allowed list", path=str(fpath), details={"ext": ext})
                    continue

            # Passed all checks; yield metadata
            rel = fpath.relative_to(scope)
            item = {"path": fpath, "relpath": rel, "size": size}
            notifier.ok("Enumerated file", path=str(fpath), details={"relpath": str(rel), "size": size})
            yield item

            file_count += 1
