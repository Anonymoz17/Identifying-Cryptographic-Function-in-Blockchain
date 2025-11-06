"""Instruction pattern heuristics (stub).

Detects bitwise-heavy blocks, rotate/shift loops, and other patterns that
often indicate crypto primitives.
"""
from typing import List, Dict


def instruction_patterns_heuristic(ghidra_export: Dict, metadata: Dict) -> List[Dict]:
    """Return a list of instruction-pattern findings.

    Stub returns an empty list.
    """
    # TODO: parse ghidra_export and detect patterns
    return []
