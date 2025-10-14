"""auditor.case

Minimal case manager for engagements. Handles creating an engagement
metadata file and immutably copying/recording a policy baseline.

This is a small scaffold to start implementing the Auditor Edition pipeline.
"""
from __future__ import annotations

import json
from pathlib import Path
import datetime
from datetime import timezone
import hashlib
from typing import Dict, Any


def _atomic_write_text(path: Path, text: str) -> None:
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(text, encoding='utf-8')
    tmp.replace(path)


class Engagement:
    """Represents an audit engagement.

    On creation it writes `engagement.json` (metadata) inside the working
    directory and stores an immutable copy of `policy.baseline.json` if given.
    It also initializes an append-only audit log (external module).
    """

    def __init__(self, workdir: str, case_id: str, client: str, scope: str):
        self.workdir = Path(workdir).resolve()
        self.workdir.mkdir(parents=True, exist_ok=True)
        self.case_id = case_id
        self.client = client
        self.scope = scope
        self.created_at = datetime.datetime.now(timezone.utc).isoformat()
        self.metadata_path = self.workdir / "engagement.json"

    def write_metadata(self) -> str:
        payload: Dict[str, Any] = {
            "case_id": self.case_id,
            "client": self.client,
            "scope": self.scope,
            "created_at": self.created_at,
        }
        # deterministic JSON
        text = json.dumps(payload, sort_keys=True, ensure_ascii=False, indent=2)
        _atomic_write_text(self.metadata_path, text)
        return str(self.metadata_path)

    def import_policy_baseline(self, baseline_path: str) -> str:
        """Copy the policy baseline into the workdir as `policy.baseline.json`.

        Returns the path to the copied file.
        """
        dest = self.workdir / "policy.baseline.json"
        data = Path(baseline_path).read_bytes()
        dest.write_bytes(data)
        # record digest for immutability reference
        d = hashlib.sha256(data).hexdigest()
        (dest.with_suffix(dest.suffix + '.sha256')).write_text(d, encoding='utf-8')
        return str(dest)


if __name__ == "__main__":
    # tiny demo
    e = Engagement(workdir="./case_demo", case_id="CASE-001", client="ACME Corp", scope="/repo")
    print("metadata:", e.write_metadata())
    print("policy copy (none) skipped")
