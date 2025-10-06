# core/recommender.py
from typing import List, Dict, Tuple
from .kb import list_algorithms, get_scores
from .scoring import score_algorithm

def top_n(n: int = 3) -> List[Tuple[str, float]]:
    """
    Returns list of (alg_id, score) sorted desc by score.
    """
    algs = list_algorithms()
    ranked = sorted(((a.id, score_algorithm(a.id)) for a in algs),
                    key=lambda x: x[1], reverse=True)
    return ranked[:max(0, n)]

def compare(a_id: str, b_id: str) -> Dict[str, Tuple[int, int]]:
    """
    Per-metric values (A,B) for UI tables/charts.
    Keys: security, performance, adoption, compatibility, risk
    """
    a = get_scores(a_id).metrics
    b = get_scores(b_id).metrics
    keys = ["security", "performance", "adoption", "compatibility", "risk"]
    return {k: (int(a.get(k, 0)), int(b.get(k, 0))) for k in keys}
