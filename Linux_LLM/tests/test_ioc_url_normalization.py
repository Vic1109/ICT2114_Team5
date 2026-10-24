"""URL canonicalization regressions; no network or model is required."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from ioc_normalizer import IOCNormalizer  # noqa: E402


class URLCanonicalizationTests(unittest.TestCase):
    def test_invalid_ports_are_rejected_without_aborting_extraction(self):
        for value in (
            "https://relay.example:notaport/path",
            "https://relay.example:99999/path",
            "https://relay.example:-1/path",
            "https://[2001:db8::1]:notaport/path",
        ):
            with self.subTest(value=value):
                self.assertIsNone(IOCNormalizer.canonical_url(value))

    def test_domain_url_normalization_and_prose_punctuation_are_preserved(self):
        cases = (
            ("hxxps://Relay[.]example:443/Path?q=Value#fragment", "https://relay.example/Path?q=Value"),
            ("https://relay.example/path]", "https://relay.example/path"),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                self.assertEqual(IOCNormalizer.canonical_url(value), expected)


if __name__ == "__main__":
    unittest.main()
