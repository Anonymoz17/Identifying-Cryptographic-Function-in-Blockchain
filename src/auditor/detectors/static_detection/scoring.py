"""Deterministic scoring aggregator.

Normalizes heuristic 'confidence' values into a `score` between 0.0 and 1.0,
adds minimal provenance and ensures each finding has an `id` and `score`.
"""
from typing import List, Dict, Any
import hashlib


def _ensure_id(f: Dict[str, Any]) -> str:
    if "id" in f and f["id"]:
        return f["id"]
    # deterministic id from content
    s = (f.get("type", "") + ":" + str(f.get("evidence_snippet", "")))
    return hashlib.sha1(s.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _clamp(v: float) -> float:
    try:
        v = float(v)
    except Exception:
        return 0.0
    if v != v:  # NaN
        return 0.0
    if v < 0.0:
        return 0.0
    if v > 1.0:
        return 1.0
    return v


def aggregate_scores(findings: List[Dict], weights: Dict = None) -> List[Dict]:
    """Return findings with `score` and normalized evidence fields.

    Strategy (simple):
    - Use `confidence` from heuristics if present (assumed 0.0-1.0); clamp.
    - If absent, derive a small default score (0.05).
    - Add `evidence` object containing `reason_tags` and `snippet`.
    - Sort findings by score desc for consistent output.
    """
    out: List[Dict] = []
    for f in findings:
        f_copy: Dict[str, Any] = dict(f)
        fid = _ensure_id(f_copy)
        f_copy.setdefault("id", fid)
        conf = f_copy.get("confidence")
        if conf is None:
            # derive from other signals if available
            if f_copy.get("count"):
                # more repeats -> higher confidence
                conf = min(0.05 + 0.12 * f_copy.get("count"), 0.9)
            else:
                conf = 0.05
        score = _clamp(conf)
        f_copy["score"] = score
        # evidence packaging
        evidence = {
            "reason_tags": f_copy.get("reason_tags", []),
            "snippet": f_copy.get("evidence_snippet"),
        }
        f_copy["evidence"] = evidence
        out.append(f_copy)

    # deterministic ordering: by score desc then id
    out.sort(key=lambda x: (-x.get("score", 0.0), x.get("id", "")))
    return out
