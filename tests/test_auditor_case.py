import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from auditor.case import Engagement


class TestAuditorCase(unittest.TestCase):
    def test_write_metadata_and_import_policy(self):
        with tempfile.TemporaryDirectory() as td:
            wd = Path(td)
            e = Engagement(
                workdir=str(wd), case_id="CASE-123", client="Client X", scope="/repo"
            )
            meta_path = e.write_metadata()
            self.assertTrue(Path(meta_path).exists())
            j = json.loads(Path(meta_path).read_text(encoding="utf-8"))
            self.assertEqual(j.get("case_id"), "CASE-123")

            # create a baseline file and import it
            baseline = wd / "policy.json"
            baseline.write_text('{"policy": "ok"}', encoding="utf-8")
            dest = e.import_policy_baseline(str(baseline))
            self.assertTrue(Path(dest).exists())
            sidecar = Path(dest).with_suffix(Path(dest).suffix + ".sha256")
            self.assertTrue(sidecar.exists())
            expected_sha = hashlib.sha256(baseline.read_bytes()).hexdigest()
            self.assertEqual(sidecar.read_text(encoding="utf-8"), expected_sha)


if __name__ == "__main__":
    unittest.main()
