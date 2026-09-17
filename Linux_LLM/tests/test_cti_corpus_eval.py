#!/usr/bin/env python3
"""Run labelled CTI extraction evaluation when the local report corpus exists."""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path


TOOLS_DIR = Path(__file__).resolve().parents[1] / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))

from evaluate_cti_quality import evaluate  # noqa: E402


class CorpusExtractionEvalTests(unittest.TestCase):
    def test_labelled_extraction_against_cti_hal_reports(self):
        reports_root = Path(
            os.getenv("CTI_REPORTS_DIR", str(Path.home() / "Desktop/CTI-Folder/CTI-HAL-main/reports"))
        )
        gold = TOOLS_DIR / "eval_fixtures" / "cti_extraction_gold.json"
        if not reports_root.is_dir():
            self.skipTest(f"CTI report corpus is not present at {reports_root}")
        result = evaluate(reports_root, gold)
        self.assertTrue(result["documents"], result)
        missing = [doc["relative_path"] for doc in result["documents"] if doc.get("error") == "missing"]
        self.assertFalse(missing, missing)
        self.assertGreaterEqual(result["tp"], 8, json.dumps(result, indent=2))
        self.assertLessEqual(result["fp"], 3, json.dumps(result, indent=2))
        self.assertEqual(result["fn"], 0, json.dumps(result, indent=2))
        self.assertGreaterEqual(result["precision"] or 0, 0.8)
        self.assertGreaterEqual(result["recall"] or 0, 0.85)


if __name__ == "__main__":
    unittest.main()
