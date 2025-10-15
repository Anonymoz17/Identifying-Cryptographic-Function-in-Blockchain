# Tests for file_handler utilities and FileHandler class
import tempfile
import unittest
from pathlib import Path

from file_handler import FileHandler, categorize_file, parse_drop_data


class TestFileHandler(unittest.TestCase):
    def test_categorize_common_extensions(self):
        self.assertEqual(
            categorize_file("foo.exe", "application/x-dosexec"), "binary-pe"
        )
        self.assertEqual(
            categorize_file("lib.so", "application/x-executable"), "binary-elf"
        )
        self.assertEqual(categorize_file("script.py", "text/x-python"), "source-python")
        self.assertEqual(
            categorize_file("archive.zip", "application/zip"), "archive-zip"
        )
        self.assertEqual(
            categorize_file("unknown.bin", "application/octet-stream"), "unknown"
        )

    def test_parse_drop_data_variants(self):
        self.assertEqual(parse_drop_data(""), [])
        self.assertEqual(parse_drop_data("{C:\\My File.txt}"), ["C:\\My File.txt"])
        self.assertEqual(
            parse_drop_data("plain.txt other.txt"), ["plain.txt", "other.txt"]
        )
        # file:// with leading slash should be normalized
        out = parse_drop_data("{file:///C:/path/to/file.txt}")
        self.assertTrue(
            out[0].endswith("C:/path/to/file.txt")
            or out[0].endswith("C:\\path\\to\\file.txt")
        )

    def test_handle_input_file_and_collision(self):
        with tempfile.TemporaryDirectory() as td:
            td_path = Path(td)
            # create a sample file
            f1 = td_path / "sample.bin"
            f1.write_bytes(b"hello")

            # use a custom upload dir inside temp dir
            upload_dir = td_path / "uploads"
            fh = FileHandler(str(upload_dir))

            meta1 = fh.handle_input(str(f1))
            self.assertIn("filename", meta1)
            self.assertEqual(meta1["size"], 5)
            stored1 = Path(meta1["stored_path"])
            self.assertTrue(stored1.exists())

            # copy same file again to simulate collision
            meta2 = fh.handle_input(str(f1))
            self.assertNotEqual(meta1["filename"], meta2["filename"])
            self.assertTrue("(" in meta2["filename"])

    def test_handle_input_http_raises(self):
        fh = FileHandler(upload_dir=tempfile.gettempdir())
        with self.assertRaises(ValueError):
            fh.handle_input("http://example.com/file")


if __name__ == "__main__":
    unittest.main()
