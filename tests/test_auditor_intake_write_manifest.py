import unittest
import tempfile
from pathlib import Path
import json
from auditor.intake import enumerate_inputs, write_manifest

class TestAuditorIntakeManifest(unittest.TestCase):
    def test_write_manifest_structure(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            # create a sample file
            f = td_path / 'x.txt'
            f.write_text('data')
            items = enumerate_inputs([str(td_path)])
            manifest_path = td_path / 'manifest.json'
            write_manifest(str(manifest_path), items)
            self.assertTrue(manifest_path.exists())
            m = json.loads(manifest_path.read_text(encoding='utf-8'))
            self.assertIn('generated_at', m)
            self.assertIn('items', m)
            self.assertIsInstance(m['items'], list)
            # items should contain at least one entry with path matching our file
            names = {Path(i['path']).name for i in m['items']}
            self.assertIn('x.txt', names)

if __name__ == '__main__':
    unittest.main()

