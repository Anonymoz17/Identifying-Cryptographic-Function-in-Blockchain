"""Generate derived static preproc artifacts (skeleton).

This module will generate normalized artifacts such as `sections.json`,
`strings.json`, `imports.json`, `constants.json`, and `entropy_map.json`.
The current file contains low-risk, no-op stubs for the quick-profile path.
"""
from typing import Dict
import os
import json


def generate_static_preproc(preproc_dir: str, out_dir: str, profile: str = "quick") -> Dict[str, str]:
    """Generate quick static preproc artifacts and return paths.

    The stub writes minimal JSON files to `out_dir` and returns a mapping of
    artifact names to paths.
    """
    os.makedirs(out_dir, exist_ok=True)
    artifacts = {}
    for name in ("sections.json", "strings.json", "imports.json", "constants.json", "entropy_map.json"):
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"generated": True, "profile": profile, "name": name}, fh)
        artifacts[name] = path

    return artifacts
