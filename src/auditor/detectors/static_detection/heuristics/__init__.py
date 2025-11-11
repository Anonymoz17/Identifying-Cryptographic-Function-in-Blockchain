"""Heuristics package for static detection.

Individual heuristics live here (signature, instruction patterns, constants).
Each heuristic should expose a function `heuristic(ghidra_export, metadata)`
returning a list of findings (dictionaries).
"""

from .signature import signature_heuristic  # noqa: F401
from .instruction_patterns import instruction_patterns_heuristic  # noqa: F401
from .constants import constants_heuristic  # noqa: F401

__all__ = [
    "signature_heuristic",
    "instruction_patterns_heuristic",
    "constants_heuristic",
]
