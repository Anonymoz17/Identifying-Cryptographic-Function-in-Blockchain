from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional


@dataclass
class SetupConfig:
    """Configuration for the setup pipeline."""

    exclude_dirs: tuple = (".git", "node_modules", "__pycache__")
    allowed_exts: Optional[tuple] = None
    max_file_size: Optional[int] = None
    extract_archives: bool = False
    archive_exts: tuple = (".zip", ".tar", ".gz", ".bz2")
    skip_symlinks: bool = True
    forbid_root: bool = True
    # Whether to allow prebuilt binary libraries (e.g., .so/.dll/.a) to be
    # included for preprocessing. Default: False (skip such binaries).
    allow_binary_libs: bool = False


@dataclass
class SetupContext:
    """Runtime context passed between setup pipeline steps."""

    scope: Path
    workdir: Path
    case_id: str
    client: Optional[object] = None
    config: SetupConfig = field(default_factory=SetupConfig)

    # derived targets (filled by path_validation)
    case_dir: Optional[Path] = None
    preproc_dir: Optional[Path] = None
    manifest_path: Optional[Path] = None

    # runtime stats container
    stats: Dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> Dict:
        return {
            "scope": str(self.scope),
            "workdir": str(self.workdir),
            "case_id": self.case_id,
            "client": self.client,
            "case_dir": str(self.case_dir) if self.case_dir else None,
            "preproc_dir": str(self.preproc_dir) if self.preproc_dir else None,
            "manifest_path": str(self.manifest_path) if self.manifest_path else None,
            "config": {
                "exclude_dirs": self.config.exclude_dirs,
                "allowed_exts": self.config.allowed_exts,
                "max_file_size": self.config.max_file_size,
                "extract_archives": self.config.extract_archives,
            },
            "stats": self.stats,
        }


# Backwards-compatible aliases: older code imported `FlowConfig` / `FlowContext`.
# Prefer `SetupConfig` / `SetupContext` going forward.
FlowConfig = SetupConfig
FlowContext = SetupContext
