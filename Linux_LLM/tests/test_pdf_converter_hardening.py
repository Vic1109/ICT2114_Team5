"""Regression tests for local-only, bounded PDF rendering."""

from __future__ import annotations

import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from pdf_converter import (  # noqa: E402
    MAX_BATCH_REPORTS,
    MAX_MARKDOWN_BYTES,
    EnhancedPDFConverter,
    create_enhanced_pdf_api_handlers,
)


class LocalResourceTests(unittest.TestCase):
    def test_only_bounded_image_resources_inside_reports_root_are_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "chart.png"
            image.write_bytes(b"png")
            self.assertEqual(
                EnhancedPDFConverter._resolve_local_resource(image.as_uri(), root),
                image.resolve(),
            )

            outside = root.parent / f"outside-{root.name}.png"
            outside.write_bytes(b"png")
            try:
                for value in ("https://example.invalid/a.png", outside.as_uri()):
                    with self.assertRaises(ValueError):
                        EnhancedPDFConverter._resolve_local_resource(value, root)

                text = root / "secret.txt"
                text.write_text("not an image", encoding="utf-8")
                with self.assertRaises(ValueError):
                    EnhancedPDFConverter._resolve_local_resource(text.as_uri(), root)

                link = root / "escape.png"
                link.symlink_to(outside)
                with self.assertRaises(ValueError):
                    EnhancedPDFConverter._resolve_local_resource(link.as_uri(), root)
            finally:
                outside.unlink(missing_ok=True)

    def test_api_factory_reuses_injected_converter(self):
        converter = EnhancedPDFConverter()
        with tempfile.TemporaryDirectory() as directory:
            handlers = create_enhanced_pdf_api_handlers(Path(directory), converter=converter)
        self.assertIs(handlers.pdf_converter, converter)


class AsyncRenderingTests(unittest.IsolatedAsyncioTestCase):
    async def test_sync_renderer_runs_off_event_loop_thread(self):
        converter = EnhancedPDFConverter()
        event_loop_thread = threading.get_ident()
        observed = {}

        def render(*_args, **_kwargs):
            observed["thread"] = threading.get_ident()
            return True

        converter._convert_with_weasyprint_sync = render
        result = await converter._convert_with_weasyprint(
            Path("input.md"), Path("output.pdf"), Path("."), None
        )
        self.assertTrue(result)
        self.assertNotEqual(observed["thread"], event_loop_thread)

    async def test_oversized_markdown_is_rejected_before_rendering(self):
        converter = EnhancedPDFConverter()
        converter.conversion_available = True
        converter.conversion_method = "weasyprint"
        converter._convert_with_weasyprint = mock.AsyncMock(return_value=True)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            markdown = root / "large.md"
            with markdown.open("wb") as handle:
                handle.truncate(MAX_MARKDOWN_BYTES + 1)
            result = await converter.convert_markdown_to_pdf(markdown, root)
        self.assertIsNone(result)
        converter._convert_with_weasyprint.assert_not_awaited()

    async def test_batch_report_count_is_bounded(self):
        converter = EnhancedPDFConverter()
        converter.conversion_available = True
        converter.conversion_method = "weasyprint"
        converter.convert_markdown_to_pdf = mock.AsyncMock()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for index in range(MAX_BATCH_REPORTS + 1):
                (root / f"report-{index}.md").touch()
            result = await converter.batch_convert_reports(root)
        self.assertEqual(result["total_processed"], MAX_BATCH_REPORTS + 1)
        self.assertTrue(result["errors"])
        converter.convert_markdown_to_pdf.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
