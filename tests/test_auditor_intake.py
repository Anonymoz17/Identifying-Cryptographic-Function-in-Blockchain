import unittest
import tempfile
from pathlib import Path
import os
import threading
from auditor.intake import hash_file_sha256, enumerate_inputs, count_inputs, OperationCancelled

class TestAuditorIntake(unittest.TestCase):
    def test_hash_file_sha256_and_count(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            f = td_path / 'a.txt'
            f.write_text('hello')
            h = hash_file_sha256(str(f))
            # known sha256 of 'hello' (no newline)
            import hashlib
            self.assertEqual(h, hashlib.sha256(b'hello').hexdigest())
            # count_inputs
            self.assertEqual(count_inputs([str(td_path)]), 1)

    def test_enumerate_inputs_directory(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            (td_path / 'f1.bin').write_bytes(b'abc')
            (td_path / 'f2.bin').write_bytes(b'defg')
            items = enumerate_inputs([str(td_path)])
            paths = {Path(i['path']).name for i in items}
            self.assertIn('f1.bin', paths)
            self.assertIn('f2.bin', paths)

    def test_hash_cancellation(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            # create a reasonably large file to allow cancellation
            big = td_path / 'big.bin'
            big.write_bytes(b'a'*1000000)
            cancel_event = threading.Event()

            # start hashing in background thread and cancel quickly
            result = []
            def worker():
                try:
                    enumerate_inputs([str(big)], cancel_event=cancel_event)
                except Exception as e:
                    result.append(type(e))

            t = threading.Thread(target=worker)
            t.start()
            cancel_event.set()
            t.join(timeout=2)
            # no exception types appended (cooperative cancel) but thread should finish
            self.assertFalse(t.is_alive())

if __name__ == '__main__':
    unittest.main()

