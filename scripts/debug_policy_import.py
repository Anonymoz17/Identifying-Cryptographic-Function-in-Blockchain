import json
import shutil
import sys
from pathlib import Path


def main() -> None:
    # ensure src/ is on sys.path when running this script
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

    from auditor.auditlog import AuditLog
    from auditor.case import Engagement
    from policy_import import import_and_record_policy

    root = Path("tmp_policy_test")
    if root.exists():
        shutil.rmtree(root)
    root.mkdir()
    policy = {"metadata": {"version": "1.0"}, "whitelist": {"file_hashes": []}}
    policy_path = root / "policy.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")

    workdir = root / "workdir"
    eng = Engagement(str(workdir), "CASE-DBG", "dbg", str(root))
    eng.write_metadata()

    auditlog_path = workdir / "auditlog.ndjson"
    ok, info = import_and_record_policy(eng, str(policy_path), str(auditlog_path))
    print("ok:", ok)
    print("info:", info)
    print("auditlog exists:", auditlog_path.exists())
    if auditlog_path.exists():
        print("auditlog last:", AuditLog(str(auditlog_path))._last_record())

    print("dest files:", list((workdir).glob("*")))


if __name__ == "__main__":
    main()
