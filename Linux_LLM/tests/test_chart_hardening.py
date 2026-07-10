"""Chart concurrency and file-permission regressions."""

from __future__ import annotations

import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from charts import SOCChartGenerator  # noqa: E402


class ChartStorageTests(unittest.TestCase):
    def test_chart_directory_and_output_use_private_modes(self):
        with tempfile.TemporaryDirectory() as directory:
            chart_root = Path(directory) / "charts"
            generator = SOCChartGenerator(str(chart_root))
            output = chart_root / "test.png"

            def fake_save(path, **_kwargs):
                Path(path).write_bytes(b"png")

            with mock.patch("charts.plt.savefig", side_effect=fake_save):
                generator._save_chart(output)

            self.assertEqual(stat.S_IMODE(chart_root.stat().st_mode), 0o750)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o640)


if __name__ == "__main__":
    unittest.main()
