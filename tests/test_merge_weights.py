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


def test_fused_confidence_simple():
    d1 = make_det("a", 0, "r1", "yara", conf=0.8)
    d2 = make_det("a", 0, "r1", "binary-regex", conf=0.6)
    merged = dedupe_detections([d1, d2])
    assert len(merged) == 1
    m = merged[0]
    # compute expected fused: (0.8*0.9 + 0.6*0.65) / (0.9 + 0.65)
    expected = (0.8 * 0.9 + 0.6 * 0.65) / (0.9 + 0.65)
    assert abs(m.details.get("fused_confidence") - expected) < 1e-6


def test_fused_confidence_with_missing_confidence():
    d1 = make_det("a", 0, "r1", "yara", conf=None)
    d2 = make_det("a", 0, "r1", "binary-regex", conf=0.6)
    merged = dedupe_detections([d1, d2])
    assert len(merged) == 1
    m = merged[0]
    # d1 has no confidence, treat as engine trust (0.9)
    expected = (0.9 * 0.9 + 0.6 * 0.65) / (0.9 + 0.65)
    assert abs(m.details.get("fused_confidence") - expected) < 1e-6
