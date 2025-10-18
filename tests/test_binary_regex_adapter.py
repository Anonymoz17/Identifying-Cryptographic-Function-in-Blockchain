from src.detectors.adapter import BinaryRegexAdapter


def test_binary_regex_adapter_matches_bytes(tmp_path):
    p = tmp_path / "bin.dat"
    p.write_bytes(b"AA\x00MAGIC\x01BB")

    rules = {"magic_bytes": b"MAGIC"}
    a = BinaryRegexAdapter(rules)
    results = list(a.scan_files([str(p)]))
    assert len(results) == 1
    r = results[0]
    assert r.rule == "magic_bytes"
    assert r.offset == 3
    assert "match_bytes" in r.details
    assert r.engine == "binary-regex"
