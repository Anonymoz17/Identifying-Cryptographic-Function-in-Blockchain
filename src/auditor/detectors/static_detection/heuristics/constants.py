"""Constants/table detection heuristics (stub).

Detects high-entropy tables, S-box-like arrays, and other embedded
constant structures.
"""
from typing import List, Dict


def constants_heuristic(ghidra_export: Dict, metadata: Dict) -> List[Dict]:
    """Return a list of constants findings. Stub returns empty list."""
    # TODO: implement entropy scanning and table shape detection
    return []
