"""Create `hints.json` and redacted `hints_public.json` (skeleton).

The hints contain prioritized addresses/ranges for the dynamic harness.
This module will generate both full and redacted variants.
"""
from typing import Dict, List
import json
import os


def generate_hints(findings: List[Dict], out_dir: str, redact: bool = False) -> str:
    """Write hints JSON to out_dir and return the path.

    Stub: writes a minimal hints file.
    """
    os.makedirs(out_dir, exist_ok=True)
    file_name = "hints_public.json" if redact else "hints.json"
    path = os.path.join(out_dir, file_name)
    payload = {"hints": findings, "redacted": redact}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh)
    return path
