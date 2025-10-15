# Tests for core.models dataclasses
import unittest
from core.models import Algorithm, ScoreCard

class TestCoreModels(unittest.TestCase):
    def test_algorithm_immutable_and_fields(self):
        a = Algorithm('x', 'Name', 'FAM', 'hash', 'recommended', 'summary')
        self.assertEqual(a.id, 'x')
        self.assertEqual(a.family, 'FAM')
        # verify dataclass is declared frozen
        self.assertTrue(getattr(a.__class__, '__dataclass_params__').frozen)

    def test_scorecard_metrics_and_rationale(self):
        sc = ScoreCard(metrics={'security': 50, 'performance': 60, 'risk': 10}, rationale={'security': 'ok'})
        self.assertIn('security', sc.metrics)
        self.assertEqual(sc.metrics['risk'], 10)
        # verify dataclass is declared frozen; note: mutating nested dicts is allowed
        self.assertTrue(getattr(sc.__class__, '__dataclass_params__').frozen)

if __name__ == '__main__':
    unittest.main()
