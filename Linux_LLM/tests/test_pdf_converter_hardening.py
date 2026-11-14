"""Regression tests for local-only, bounded PDF rendering."""

from __future__ import annotations

import struct
import sys
import tempfile
import threading
import unittest
import zlib
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


def _tiny_png() -> bytes:
    def chunk(tag: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(tag + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", crc)

    header = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    pixels = zlib.compress(b"\x00\xff\x00\x00")
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", pixels) + chunk(b"IEND", b"")


class WeasyPrint70FetcherTests(unittest.TestCase):
    def test_local_chart_renders_without_the_removed_default_fetcher(self):
        import pdf_converter

        if pdf_converter.weasyprint is None:
            self.skipTest("WeasyPrint is not installed")
        self.assertFalse(hasattr(pdf_converter.weasyprint, "default_url_fetcher"))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            chart_dir = root / "charts"
            chart_dir.mkdir()
            chart = chart_dir / "timeline.png"
            chart.write_bytes(_tiny_png())
            markdown = root / "report.md"
            markdown.write_text("# Report\n\n![Chart](./charts/timeline.png)\n", encoding="utf-8")

            fetcher = EnhancedPDFConverter._local_only_url_fetcher(root)
            self.assertFalse(fetcher._fail_on_errors)
            from weasyprint.urls import URLFetchingError, fetch

            with fetch(fetcher, chart.as_uri()) as response:
                self.assertTrue(response.read().startswith(b"\x89PNG"))
            with self.assertRaises(URLFetchingError):
                with fetch(fetcher, "https://example.invalid/a.png"):
                    pass

            pdf_path = root / "report.pdf"
            converter = EnhancedPDFConverter()
            rendered = converter._convert_with_weasyprint_sync(markdown, pdf_path, root)
            self.assertTrue(rendered)
            self.assertTrue(pdf_path.read_bytes().startswith(b"%PDF"))


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
