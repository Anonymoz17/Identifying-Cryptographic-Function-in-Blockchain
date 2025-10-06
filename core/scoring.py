# core/scoring.py
from typing import Dict, Optional
from .kb import get_scores

# Free-tier default weights
DEFAULT_WEIGHTS: Dict[str, float] = {
    "security": 0.40,
    "performance": 0.20,
    "adoption": 0.20,
    "compatibility": 0.10,
    "risk": 0.10,  # note: we invert risk = 100 - risk
}

def score_algorithm(alg_id: str, weights: Optional[Dict[str, float]] = None) -> float:
    """
    Weighted score in [0, 100]. Risk is inverted so lower risk => higher score.
    """
    w = weights or DEFAULT_WEIGHTS
    s = get_scores(alg_id).metrics
    # Ensure missing keys don’t crash
    sec = s.get("security", 0)
    perf = s.get("performance", 0)
    adop = s.get("adoption", 0)
    comp = s.get("compatibility", 0)
    risk_inv = 100 - s.get("risk", 50)

    total = (
        sec  * w.get("security", 0) +
        perf * w.get("performance", 0) +
        adop * w.get("adoption", 0) +
        comp * w.get("compatibility", 0) +
        risk_inv * w.get("risk", 0)
    )
    # Clamp to [0,100] just in case
    return max(0.0, min(100.0, total))
