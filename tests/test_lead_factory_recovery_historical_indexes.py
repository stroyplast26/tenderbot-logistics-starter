from __future__ import annotations

import unittest

from lead_factory.recovery import _OPTIONAL_HISTORICAL_INDEX_SPECS
from lead_factory.store import SCHEMA


class HistoricalIndexCompatibilityTests(unittest.TestCase):
    def test_suppression_index_pin_matches_canonical_stage_schema(self):
        expected = _OPTIONAL_HISTORICAL_INDEX_SPECS[
            ("index", "uq_lf_active_suppression")
        ]
        self.assertIn("where state='ACTIVE'", expected)
        self.assertIn("WHERE state='ACTIVE'", SCHEMA)


if __name__ == "__main__":
    unittest.main()
