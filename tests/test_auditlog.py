import tempfile
import unittest
from pathlib import Path

from auditor.auditlog import AuditLog


class TestAuditLog(unittest.TestCase):
    def test_append_and_verify(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "auditlog.ndjson"
            al = AuditLog(str(p))
            _ = al.append("engagement.created", {"case": "CASE-001"})
            _ = al.append("inputs.added", {"count": 1})
            self.assertTrue(al.verify())

    def test_tamper_detection(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "auditlog.ndjson"
            al = AuditLog(str(p))
            al.append("a", {"x": 1})
            al.append("b", {"y": 2})
            # tamper: change second line
            txt = p.read_text(encoding="utf-8")
            parts = txt.splitlines()
            # modify payload of second record
            if len(parts) >= 2:
                import json

                rec = json.loads(parts[1])
                rec["payload"]["y"] = 999
                parts[1] = json.dumps(rec, sort_keys=True, ensure_ascii=False)
                p.write_text("\n".join(parts) + "\n", encoding="utf-8")
            ok, diag = al.verify_with_diagnostics()
            self.assertFalse(ok)
            self.assertIsNotNone(diag)


if __name__ == "__main__":
    unittest.main()
