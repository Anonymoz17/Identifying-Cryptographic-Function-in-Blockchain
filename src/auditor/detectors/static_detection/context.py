"""Typed dataclasses for static detection run context and results.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Optional, Any


@dataclass
class ToolVersions:
    ghidra: Optional[str] = None
    frida: Optional[str] = None
    other: Dict[str, str] = field(default_factory=dict)


@dataclass
class RunContext:
    file_hash: str
    preproc_dir: str
    analysis_base: str
    profile: str = "quick"  # 'quick' | 'full'
    force: bool = False
    requested_by: Optional[str] = None
    tool_versions: ToolVersions = field(default_factory=ToolVersions)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    # If True and multiple preproc/<hash>/ candidates exist under a case
    # root, automatically select the most-recent one (by input.bin mtime).
    auto_select_latest: bool = False


@dataclass
class RunResult:
    file_hash: str
    hints_path: Optional[str] = None
    static_results_path: Optional[str] = None
    cached: bool = False
    summary: Dict[str, Any] = field(default_factory=dict)
    errors: Optional[list] = None
