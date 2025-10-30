from pathlib import Path

from src.detectors.adapter import RegexAdapter


def test_yara_or_regex_matches_sample_files():
    repo = Path(__file__).resolve().parents[1]
    samples = [
        repo / "tools" / "sample_scope" / "aes_sample.txt",
        repo / "tools" / "sample_scope" / "contract_sample.sol",
    ]
    for s in samples:
        assert s.exists(), f"sample file missing: {s}"

    # Try using yara adapter if available; otherwise use a regex fallback
    yara_rules = Path(repo / "src" / "detectors" / "yara" / "crypto_extended.yar")
    patterns = {"crypto_fallback": r"sha|sha256|AES|keccak|ecrecover|HMAC|ECDSA|RSA"}

    # If yara runtime isn't available in the test environment, use RegexAdapter directly
    try:
        from src.detectors.adapter import YaraAdapter

        try:
            ya = YaraAdapter(rules_path=str(yara_rules))
            adapter = ya
        except Exception:
            adapter = RegexAdapter(patterns)
    except Exception:
        adapter = RegexAdapter(patterns)

    # Run scan
    detections = list(adapter.scan_files([str(p) for p in samples]))
    assert len(detections) >= 1
    engines = {d.engine for d in detections}
    # engine may be 'yara' or 'regex' depending on runtime availability
    assert any(e in ("yara", "regex", "yara-fallback") for e in engines)
