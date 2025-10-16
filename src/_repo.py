"""Repository utilities.

Provides a small helper to find the repository root (by walking up for
pyproject.toml, setup.cfg or .git) so code and tests can robustly compute
paths independent of package layout.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional


def find_repo_root(start: Optional[Path] = None) -> Path:
    """Return the repo root Path by looking for common markers.

    Walks parents until a directory containing 'pyproject.toml', 'setup.cfg'
    or '.git' is found. If none found, returns the filesystem root of start.
    """
    p = Path(start or Path(__file__).resolve())
    # start from parent directory (module lives under src/)
    if p.is_file():
        p = p.parent
    for d in [p] + list(p.parents):
        if (
            (d / "pyproject.toml").exists()
            or (d / "setup.cfg").exists()
            or (d / ".git").exists()
        ):
            return d
    # fallback
    return p.root
