"""Signature heuristics (stub).

This heuristic matches known library signatures or import patterns. The
stub returns an empty list by default.
"""
from typing import List, Dict


def signature_heuristic(ghidra_export: Dict, metadata: Dict) -> List[Dict]:
    """Return a list of signature findings.

    Each finding is a dict with keys such as `id`, `type`, `confidence`.
    """
    # TODO: implement real signature matching
    return []
