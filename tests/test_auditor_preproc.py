import json
import tempfile
import unittest
from pathlib import Path

from auditor.preproc import preprocess_items


class TestAuditorPreproc(unittest.TestCase):
    def test_preprocess_creates_artifacts_and_index(self):
        with tempfile.TemporaryDirectory() as td:
            wd = Path(td)
            # prepare a sample file
            src_dir = wd / "inputs"
            src_dir.mkdir()
            f = src_dir / "sample.bin"
            f.write_bytes(b"hello-world")
            import datetime
            import hashlib

            sha = hashlib.sha256(b"hello-world").hexdigest()
            items = [
                {
                    "path": str(f),
                    "size": f.stat().st_size,
                    "mtime": datetime.datetime.fromtimestamp(
                        f.stat().st_mtime, datetime.timezone.utc
                    ).isoformat(),
                    "sha256": sha,
                }
            ]

            idx = preprocess_items(items, str(wd))
            # index entries returned
            self.assertEqual(len(idx), 1)

            art_dir = wd / "preproc" / sha
            self.assertTrue(art_dir.exists())
            # metadata.json must exist
            meta = art_dir / "metadata.json"
            self.assertTrue(meta.exists())
            mobj = json.loads(meta.read_text(encoding="utf-8"))
            self.assertEqual(mobj.get("sha256"), sha)

            # preproc.index.jsonl should exist and contain one entry
            index_path = wd / "preproc.index.jsonl"
            self.assertTrue(index_path.exists())
            lines = index_path.read_text(encoding="utf-8").splitlines()
            self.assertGreaterEqual(len(lines), 1)


if __name__ == "__main__":
    unittest.main()
