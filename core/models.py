"""Core data models for the in-memory knowledge base.

Algorithm: small immutable descriptor for a crypto primitive.
ScoreCard: holds metric scores and short rationales used by the recommender.
"""

from dataclasses import dataclass
from typing import Dict


@dataclass(frozen=True)
class Algorithm:
    id: str
    name: str
    family: str        # e.g., "SHA-2", "SHA-3", "BLAKE"
    type: str          # "hash" | "signature" | "kdf" | ...
    status: str        # "recommended" | "acceptable" | "deprecated"
    summary: str


@dataclass(frozen=True)
class ScoreCard:
    # All metrics 0–100 (risk: higher = worse; we invert in scoring)
    metrics: Dict[str, int]          # security, performance, adoption, compatibility, risk
    rationale: Dict[str, str]        # short reasons per metric (optional for UI tooltips)

