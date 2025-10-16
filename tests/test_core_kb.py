# Tests for core.kb
import unittest

from core import kb


class TestCoreKB(unittest.TestCase):
    def test_list_algorithms_contains_expected(self):
        algs = kb.list_algorithms()
        self.assertIsInstance(algs, list)
        self.assertGreaterEqual(len(algs), 3)
        # check order and ids
        ids = [a.id for a in algs]
        self.assertEqual(ids[0], "sha256")
        self.assertIn("md5", ids)

    def test_get_algorithm_and_scores(self):
        a = kb.get_algorithm("sha256")
        self.assertEqual(a.name, "SHA-256")
        sc = kb.get_scores("md5")
        self.assertIsNotNone(sc)
        self.assertIn("security", sc.metrics)
        self.assertEqual(sc.metrics["security"], 8)


if __name__ == "__main__":
    unittest.main()
