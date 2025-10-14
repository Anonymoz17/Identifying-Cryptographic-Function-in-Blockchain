import unittest
import tempfile
from pathlib import Path
import json
import zipfile
import hashlib
from auditor.evidence import build_evidence_pack

class TestAuditorEvidence(unittest.TestCase):
    def test_build_evidence_pack_creates_zip_and_sidecar(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            root = td_path / 'root'
            root.mkdir()
            # create files under root and subdir
            f1 = root / 'a.txt'
            f1.write_text('alpha')
            sub = root / 'subdir'
            sub.mkdir()
            f2 = sub / 'b.bin'
            f2.write_bytes(b'bytes')

            files = [f1, f2]
            zip_path, zip_sha = build_evidence_pack(root, 'CASE-1', files, out_dir=td_path)
            self.assertTrue(zip_path.exists())
            # sidecar
            sidecar = zip_path.with_suffix(zip_path.suffix + '.sha256')
            self.assertTrue(sidecar.exists())
            self.assertEqual(sidecar.read_text(encoding='utf-8'), zip_sha)

            # check manifest inside zip
            with zipfile.ZipFile(zip_path, 'r') as zf:
                self.assertIn('evidence_manifest.json', zf.namelist())
                manifest = json.loads(zf.read('evidence_manifest.json').decode('utf-8'))
                paths = [f['path'] for f in manifest.get('files', [])]
                self.assertIn('a.txt', paths)
                self.assertIn('subdir/b.bin', paths)
                # verify one of the file digests matches
                for entry in manifest['files']:
                    p = entry['path']
                    # resolve to original path
                    orig = root / p
                    if orig.exists():
                        self.assertEqual(entry['sha256'], hashlib.sha256(orig.read_bytes()).hexdigest())

if __name__ == '__main__':
    unittest.main()

