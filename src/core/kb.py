# core/kb.py
from typing import Dict, List

from core.models import Algorithm, ScoreCard

# Algorithms (seed)
_ALG: Dict[str, Algorithm] = {
    "sha256": Algorithm(
        "sha256",
        "SHA-256",
        "SHA-2",
        "hash",
        "recommended",
        "Widely deployed, strong for non-PQ needs.",
    ),
    "keccak": Algorithm(
        "keccak",
        "SHA-3 / Keccak-256",
        "SHA-3",
        "hash",
        "recommended",
        "NIST SHA-3; sponge construction, solid margins.",
    ),
    "blake3": Algorithm(
        "blake3",
        "BLAKE3",
        "BLAKE",
        "hash",
        "recommended",
        "Very fast, parallel; not FIPS at present.",
    ),
    "ripemd160": Algorithm(
        "ripemd160",
        "RIPEMD-160",
        "RIPEMD",
        "hash",
        "acceptable",
        "Legacy in some chains (addresses); avoid for new designs.",
    ),
    "md5": Algorithm(
        "md5",
        "MD5",
        "MD",
        "hash",
        "deprecated",
        "Broken by collisions; do not use for security.",
    ),
}

# Score cards (0–100). risk: higher = worse (will be inverted in scoring).
_SCORES: Dict[str, ScoreCard] = {
    "sha256": ScoreCard(
        metrics={
            "security": 92,
            "performance": 75,
            "adoption": 98,
            "compatibility": 94,
            "risk": 10,
        },
        rationale={
            "security": "Strong preimage/collision margins",
            "adoption": "Ubiquitous",
        },
    ),
    "keccak": ScoreCard(
        metrics={
            "security": 94,
            "performance": 72,
            "adoption": 76,
            "compatibility": 90,
            "risk": 10,
        },
        rationale={
            "security": "Standardized SHA-3",
            "compatibility": "Good libs support",
        },
    ),
    "blake3": ScoreCard(
        metrics={
            "security": 90,
            "performance": 98,
            "adoption": 58,
            "compatibility": 82,
            "risk": 12,
        },
        rationale={
            "performance": "Top-tier throughput",
            "adoption": "Growing, non-FIPS",
        },
    ),
    "ripemd160": ScoreCard(
        metrics={
            "security": 60,
            "performance": 80,
            "adoption": 65,
            "compatibility": 70,
            "risk": 55,
        },
        rationale={"security": "Legacy; not recommended for new use"},
    ),
    "md5": ScoreCard(
        metrics={
            "security": 8,
            "performance": 95,
            "adoption": 40,
            "compatibility": 75,
            "risk": 96,
        },
        rationale={"security": "Practical collisions; broken"},
    ),
}


def list_algorithms() -> List[Algorithm]:
    # stable order for UI (or sort by name)
    order = ["sha256", "keccak", "blake3", "ripemd160", "md5"]
    return [_ALG[i] for i in order]


def get_algorithm(alg_id: str) -> Algorithm:
    return _ALG[alg_id]


def get_scores(alg_id: str) -> ScoreCard:
    return _SCORES[alg_id]
