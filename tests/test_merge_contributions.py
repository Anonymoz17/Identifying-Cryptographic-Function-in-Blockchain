from src.detectors.adapter import Detection
from src.detectors.merge import dedupe_detections


def make_det(path, offset, rule, engine, conf=None):
    return Detection(
        path=path,
        offset=offset,
        rule=rule,
        details={} if conf is None else {"confidence": conf},
        engine=engine,
    )


def test_contributions_recorded():
    d1 = make_det("a", 0, "r1", "yara", conf=0.8)
    d2 = make_det("a", 0, "r1", "binary-regex", conf=0.6)
    merged = dedupe_detections([d1, d2])
    assert len(merged) == 1
    m = merged[0]
    contribs = m.details.get("contributions")
    assert "yara" in contribs and "binary-regex" in contribs
    # ensure normalized contributions sum to the fused_confidence (by design)
    norm = m.details.get("contributions_normalized")
    fused = m.details.get("fused_confidence")
    assert abs(sum(norm.values()) - fused) < 1e-6
