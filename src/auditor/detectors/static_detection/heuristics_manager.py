"""Run and manage heuristics (skeleton).

The real manager will run heuristics in parallel, collect Findngs, and
attach provenance. The stub provides a simple sequential runner.
"""
from typing import List, Dict, Callable


def run_heuristics(ghidra_export: Dict, metadata: Dict, heuristics: List[Callable]) -> List[Dict]:
    """Run provided heuristics and return list of findings.

    Each heuristic is expected to be a callable(ghidra_export, metadata) -> List[Finding]
    For the stub we call each heuristic sequentially and flatten results.
    """
    findings = []
    for h in heuristics:
        try:
            res = h(ghidra_export, metadata)
            if res:
                findings.extend(res)
        except Exception:
            # isolate heuristic failures
            continue
    return findings
