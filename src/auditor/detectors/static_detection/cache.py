"""Simple cache utilities (skeleton).

Will be extended with TTLs and invalidation. The stub provides a helper to
write a `.cache_meta.json` file recording generator versions.
"""
import json
import os
from typing import Dict


def write_cache_meta(out_dir: str, meta: Dict) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, ".cache_meta.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(meta, fh)
    return path
