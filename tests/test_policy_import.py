import json
from pathlib import Path

from auditor.auditlog import AuditLog
from auditor.case import Engagement
from policy_import import import_and_record_policy


def test_policy_import_success(tmp_path):
    # create a valid policy JSON
    policy = {
        "metadata": {"version": "1.0"},
        "whitelist": {"file_hashes": []},
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    # create engagement workspace
    workdir = tmp_path / "workdir"
    eng = Engagement(str(workdir), "CASE-TEST", "tester", str(tmp_path))
    eng.write_metadata()

    auditlog_path = workdir / "auditlog.ndjson"

    ok, info = import_and_record_policy(eng, str(policy_path), str(auditlog_path))
    assert ok
    # dest should be inside the case workdir
    dest = Path(info)
    assert dest.exists()
    # sidecar sha must exist
    sha_file = dest.with_suffix(dest.suffix + ".sha256")
    assert sha_file.exists()

    # auditlog should contain an imported event as the last record
    al = AuditLog(str(auditlog_path))
    last = al._last_record()
    assert last is not None
    assert last.get("event") == "engagement.policy_imported"
    assert last.get("payload", {}).get("source") == str(policy_path)


def test_policy_import_invalid_json(tmp_path):
    # write invalid JSON
    policy_path = tmp_path / "bad.json"
    policy_path.write_text("{ invalid json }", encoding="utf-8")

    workdir = tmp_path / "workdir2"
    eng = Engagement(str(workdir), "CASE-FAIL", "tester", str(tmp_path))
    eng.write_metadata()

    auditlog_path = workdir / "auditlog.ndjson"

    ok, info = import_and_record_policy(eng, str(policy_path), str(auditlog_path))
    assert not ok

    al = AuditLog(str(auditlog_path))
    last = al._last_record()
    assert last is not None
    assert last.get("event") == "engagement.policy_import_failed"
    assert last.get("payload", {}).get("source") == str(policy_path)
