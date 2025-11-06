"""Run and manage heuristics.

This manager calls heuristics sequentially (sufficient for the quick-profile)
and passes both the ghidra export and lightweight static preproc artifacts to
each heuristic callable.
"""
from typing import List, Dict, Callable, Any


def run_heuristics(ghidra_export: Dict, metadata: Dict, heuristics: List[Callable], static_artifacts: Dict[str, Any] = None) -> List[Dict]:
    """Run provided heuristics and return a flattened list of findings.

    Each heuristic is expected to be a callable with signature:
        heuristic(ghidra_export, metadata, static_artifacts) -> List[Finding]
    """
    findings = []
    for h in heuristics:
        try:
            res = h(ghidra_export, metadata, static_artifacts)
            if res:
                findings.extend(res)
        except Exception:
            # isolate heuristic failures
            continue
    return findings
