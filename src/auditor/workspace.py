# auditor/workspace.py
"""Helper to canonicalize engagement workspace layout and paths.

Provides a small Workspace class that computes canonical paths for an
engagement and creates directories as needed.
"""
from __future__ import annotations

from pathlib import Path
from typing import Dict


class Workspace:
    def __init__(self, base_dir: Path | str, case_id: str):
        self.base = Path(base_dir) if not isinstance(base_dir, Path) else base_dir
        # normalize
        self.base = self.base.resolve()
        # sanitize case_id to a safe filename
        safe = case_id.replace("/", "_").replace("\\", "_")
        self.case_id = safe
        self.root = self.base / self.case_id
        # primary dirs
        self.preproc_dir = self.root / "preproc"
        self.evidence_dir = self.root / "evidence"

    def ensure(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        self.preproc_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    def paths(self) -> Dict[str, Path]:
        return {
            "root": self.root,
            "engagement": self.root / "engagement.json",
            "auditlog": self.root / "auditlog.ndjson",
            "inputs_manifest": self.root / "inputs.manifest.json",
            "preproc_index": self.root / "preproc.index.jsonl",
            "preproc_dir": self.preproc_dir,
            "policy_baseline": self.root / "policy.baseline.json",
            "evidence_dir": self.evidence_dir,
        }

    def __repr__(self) -> str:
        return f"Workspace(root={self.root!s})"
