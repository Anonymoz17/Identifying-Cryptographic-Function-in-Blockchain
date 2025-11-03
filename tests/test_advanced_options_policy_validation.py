from pathlib import Path
import tempfile

from auditor.setup_flow.advanced_settings import validate_policy_path


def test_validate_policy_path_nonexistent():
    ok, msg = validate_policy_path("this/path/does/not/exist.json")
    assert not ok
    assert "not found" in msg.lower() or "error" in msg.lower()


def test_validate_policy_path_existing(tmp_path):
    p = tmp_path / "policy.json"
    p.write_text('{"policy": true}', encoding='utf-8')
    ok, msg = validate_policy_path(str(p))
    assert ok
    assert msg == ''
