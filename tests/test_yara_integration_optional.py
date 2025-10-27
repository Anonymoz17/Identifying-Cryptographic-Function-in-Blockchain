import importlib.util

import pytest

from src.detectors.adapter import YaraAdapter

HAS_YARA = importlib.util.find_spec("yara") is not None


@pytest.mark.skipif(not HAS_YARA, reason="yara-python not available")
def test_yara_integration_compile_and_match(tmp_path):
    # write a tiny yara rule to match ASCII SECRET
    rule_file = tmp_path / "test_rules.yar"
    rule_file.write_text(
        """
rule TestSecret {
    strings:
        $s1 = "SECRET"
    condition:
        $s1
}
"""
    )
    # write a sample file
    f = tmp_path / "sample.bin"
    f.write_bytes(b"xxxSECRETyyy")

    ya = YaraAdapter(rules_path=str(rule_file))
    results = list(ya.scan_files([str(f)]))
    assert len(results) >= 1
    # ensure meta/tags keys are present (empty in this rule but shape exists)
    r = results[0]
    assert r.engine == "yara"
    assert "match_bytes" in r.details or "data" in r.details
