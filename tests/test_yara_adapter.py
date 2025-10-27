from src.detectors.adapter import YaraAdapter


def test_yara_adapter_fallback_to_regex(tmp_path):
    # Ensure the environment doesn't require yara. Create a simple file and a regex rule.
    f = tmp_path / "sample.txt"
    f.write_text("this contains MAGIC_KEY and more text\n")

    rules = {"magic_rule": "MAGIC_KEY"}
    ya = YaraAdapter(rules_map=rules)

    results = list(ya.scan_files([str(f)]))
    assert len(results) == 1
    r = results[0]
    assert r.rule == "magic_rule"
    assert (
        "MAGIC_KEY" in r.details.get("match") or r.details.get("snippet") == "MAGIC_KEY"
    )
