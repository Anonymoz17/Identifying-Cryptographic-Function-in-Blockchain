"""auditor.case

Minimal case manager for engagements. Handles creating an engagement
metadata file and immutably copying/recording a policy baseline.

This is a small scaffold to start implementing the Auditor Edition pipeline.
"""
from __future__ import annotations

import json
import os
import datetime
import hashlib
from typing import Dict, Any


class Engagement:
    """Represents an audit engagement.

    On creation it writes `engagement.json` (metadata) inside the working
    directory and stores an immutable copy of `policy.baseline.json` if given.
    It also initializes an append-only audit log (external module).
    """

    def __init__(self, workdir: str, case_id: str, client: str, scope: str):
        self.workdir = os.path.abspath(workdir)
        os.makedirs(self.workdir, exist_ok=True)
        self.case_id = case_id
        self.client = client
        self.scope = scope
        self.created_at = datetime.datetime.utcnow().isoformat() + "Z"
        self.metadata_path = os.path.join(self.workdir, "engagement.json")

    def write_metadata(self) -> str:
        payload: Dict[str, Any] = {
            "case_id": self.case_id,
            "client": self.client,
            "scope": self.scope,
            "created_at": self.created_at,
        }
        with open(self.metadata_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
        return self.metadata_path

    def import_policy_baseline(self, baseline_path: str) -> str:
        """Copy the policy baseline into the workdir as `policy.baseline.json`.

        Returns the path to the copied file.
        """
        dest = os.path.join(self.workdir, "policy.baseline.json")
        with open(baseline_path, "rb") as r, open(dest, "wb") as w:
            data = r.read()
            w.write(data)
        # record digest for immutability reference
        d = hashlib.sha256(data).hexdigest()
        # write a small sidecar with the digest
        with open(dest + ".sha256", "w", encoding="utf-8") as sf:
            sf.write(d)
        return dest


if __name__ == "__main__":
    # tiny demo
    e = Engagement(workdir="./case_demo", case_id="CASE-001", client="ACME Corp", scope="/repo")
    print("metadata:", e.write_metadata())
    print("policy copy (none) skipped")
