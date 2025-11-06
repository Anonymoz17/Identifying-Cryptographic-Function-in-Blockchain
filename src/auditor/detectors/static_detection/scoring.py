"""Deterministic scoring aggregator (skeleton).

The real implementation will combine heuristic contributions into a
0.0-1.0 confidence with reproducible ordering and provenance.
"""
from typing import List, Dict


def aggregate_scores(findings: List[Dict], weights: Dict = None) -> List[Dict]:
    """Return findings with an added `score` key (stub: default 0.0).

    This is intentionally simple for the skeleton.
    """
    out = []
    for f in findings:
        f_copy = dict(f)
        f_copy.setdefault("score", 0.0)
        out.append(f_copy)
    return out
