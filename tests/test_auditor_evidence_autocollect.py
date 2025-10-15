import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from auditor.evidence import build_evidence_pack


class TestEvidenceAutoCollect(unittest.TestCase):
    def test_files_empty_triggers_autocollect(self):
        with tempfile.TemporaryDirectory() as td:
            wd = Path(td)
            # create engagement.json and a sample file and a preproc artifact
            (wd / "engagement.json").write_text(
                json.dumps({"case_id": "CASE-001"}), encoding="utf-8"
            )
            inputs_dir = wd / "preproc"
            inputs_dir.mkdir()
            sha_dir = inputs_dir / "deadbeef"
            sha_dir.mkdir()
            sample = sha_dir / "input.bin"
            sample.write_bytes(b"hello")
            meta = sha_dir / "metadata.json"
            meta.write_text(json.dumps({"sha256": "deadbeef"}), encoding="utf-8")

            # Call build_evidence_pack with explicit empty list
            zip_path, zip_sha = build_evidence_pack(wd, "CASE-001", files=[])
            self.assertTrue(zip_path.exists())
            with zipfile.ZipFile(zip_path, "r") as zf:
                names = zf.namelist()
                # Manifest should be present
                self.assertIn("evidence_manifest.json", names)
                # engagement.json should be included
                self.assertIn("engagement.json", names)
                # preproc input should be included under preproc/deadbeef/input.bin
                self.assertIn("preproc/deadbeef/input.bin", names)


if __name__ == "__main__":
    unittest.main()
