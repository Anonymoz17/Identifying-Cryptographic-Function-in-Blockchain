from __future__ import annotations

from typing import Dict, Iterable, Tuple

from .adapter import Detection


def dedupe_detections(
    detections: Iterable[Detection], engine_weights: Dict[str, float] | None = None
):
    """Deduplicate detections by (path, offset, rule).

    When multiple detections for the same key exist from different engines, this
    function merges details, records supporting engines, and computes a fused
    confidence score using per-engine weights.

    engine_weights: optional mapping of engine -> weight (0..1). If omitted,
    defaults are used.
    """
    if engine_weights is None:
        # engine_weights are trust multipliers (0..1) representing how much we trust an engine
        engine_weights = {
            "yara": 0.9,
            "yara-fallback": 0.5,
            "binary-regex": 0.65,
            "regex": 0.5,
            "semgrep-lite": 0.6,
        }

    seen: Dict[Tuple[str, int, str], Detection] = {}
    meta_support: Dict[Tuple[str, int, str], Dict] = {}

    for d in detections:
        key = (d.path, d.offset or 0, d.rule)
        if key not in seen:
            # copy detection to avoid mutating inputs
            seen[key] = d
            meta_support[key] = {
                "engines": set(),
                "weighted_conf_sum": 0.0,
                "weight_sum": 0.0,
                "contributions": {},
            }

        # merge details conservatively
        try:
            if isinstance(d.details, dict):
                seen[key].details.update(d.details)
        except Exception:
            pass

        # record engine support
        eng = getattr(d, "engine", None) or "unknown"
        meta_support[key]["engines"].add(eng)

        # determine detection-level confidence (0..1)
        det_conf = None
        if isinstance(d.details, dict) and "confidence" in d.details:
            try:
                det_conf = float(d.details.get("confidence"))
                # clamp
                det_conf = max(0.0, min(1.0, det_conf))
            except Exception:
                det_conf = None

        engine_trust = engine_weights.get(eng, 0.5)
        # fallback detection confidence if not provided
        if det_conf is None:
            det_conf = engine_trust

        # weighted contribution: detection confidence scaled by engine trust
        contribution = det_conf * engine_trust
        meta_support[key]["weighted_conf_sum"] += contribution
        meta_support[key]["weight_sum"] += engine_trust
        # record per-engine contribution
        meta_support[key]["contributions"][eng] = (
            meta_support[key]["contributions"].get(eng, 0.0) + contribution
        )

    # finalize: attach supporting engines and fused confidence
    out = []
    for key, det in seen.items():
        support = meta_support[key]
        engines = sorted(support["engines"])
        weight_sum = support["weight_sum"] or 1.0
        # fused confidence normalized to 0..1
        fused_conf = support["weighted_conf_sum"] / weight_sum
        # attach support metadata into details
        try:
            if isinstance(det.details, dict):
                det.details.setdefault("supporting_engines", engines)
                det.details.setdefault("fused_confidence", fused_conf)
                # attach raw contributions and normalized contributions
                det.details.setdefault(
                    "contributions", support.get("contributions", {})
                )
                # normalized contributions (contribution / weight_sum)
                norm = (
                    {
                        k: (v / weight_sum)
                        for k, v in support.get("contributions", {}).items()
                    }
                    if weight_sum
                    else {}
                )
                det.details.setdefault("contributions_normalized", norm)
                det.details.setdefault(
                    "engine_trusts", {k: engine_weights.get(k, 0.5) for k in engines}
                )
        except Exception:
            pass
        out.append(det)

    return out
