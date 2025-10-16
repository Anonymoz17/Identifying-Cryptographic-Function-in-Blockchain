"""Simple scoring helper for algorithms in the knowledge base.

Provides score_algorithm(alg_id) -> float which returns a numeric score
used by the recommender. The implementation uses a weighted sum of
per-metric values from core.kb.ScoreCard.metrics.
"""

from typing import Dict

from .kb import get_scores

_WEIGHTS: Dict[str, float] = {
    "security": 0.35,
    "performance": 0.2,
    "adoption": 0.2,
    "compatibility": 0.15,
    "risk": -0.1,  # higher risk reduces score
}


def score_algorithm(alg_id: str) -> float:
    """Return a 0..100 style score for an algorithm id.

    The function is intentionally simple: it reads the ScoreCard metrics
    via core.kb.get_scores and computes a weighted sum. Missing metrics
    default to 0.
    """
    sc = get_scores(alg_id)
    metrics = getattr(sc, "metrics", {})
    total = 0.0
    for k, w in _WEIGHTS.items():
        val = float(metrics.get(k, 0))
        total += w * val
    # Normalize into a 0..100 range for UI friendliness
    return max(0.0, min(100.0, total))
