import json

from policy_validator import validate_policy_text

GOOD = json.dumps(
    {
        "version": "1.0",
        "metadata": {"author": "tester"},
        "whitelist": {"file_hashes": ["abc123"]},
    }
)

BAD_JSON = "{ this is not json }"

BAD_SCHEMA = json.dumps(
    {"metadata": {"author": "x"}}
)  # missing version and whitelist/rules/scoring


def test_good_policy_validates():
    ok, errs = validate_policy_text(GOOD)
    assert ok and not errs


def test_bad_json_rejected():
    ok, errs = validate_policy_text(BAD_JSON)
    assert not ok
    assert any("JSON parse error" in e for e in errs)


def test_bad_schema_rejected():
    ok, errs = validate_policy_text(BAD_SCHEMA)
    assert not ok
    assert any(
        "Missing required 'version'" in e
        or "must contain at least one" in e
        or "required" in e
        for e in errs
    )
