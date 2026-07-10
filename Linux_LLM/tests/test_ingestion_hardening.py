"""Focused safety and lifecycle tests for CTI document ingestion."""

from __future__ import annotations

import io
import stat
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch


CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
if str(CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(CONFIG_DIR))

from rag import (  # noqa: E402
    DOCXProcessor,
    DocumentProcessor,
    DocumentSafetyError,
    DocumentValidator,
    PDFProcessor,
    YAMLProcessor,
)


class _FakePDFPage:
    def __init__(self, text: str):
        self.text = text

    def get_text(self, *_args, **_kwargs):
        return self.text

    def get_links(self):
        return []

    def get_images(self):
        return []

    def find_tables(self):
        return None


class _FakePDFDocument:
    def __init__(self, page_texts: list[str], *, needs_pass: bool = False):
        self.pages = [_FakePDFPage(text) for text in page_texts]
        self.needs_pass = needs_pass
        self.metadata = {
            "title": "Synthetic CTI",
            "author": "Analyst",
        }
        self.closed = False

    def __len__(self):
        return len(self.pages)

    def __getitem__(self, index):
        return self.pages[index]

    def close(self):
        self.closed = True


def _minimal_docx(
    *,
    extra_entries: list[tuple[str | zipfile.ZipInfo, bytes]] | None = None,
    compression: int = zipfile.ZIP_DEFLATED,
) -> bytes:
    document_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body><w:p><w:r><w:t>Observed domain safe.example</w:t></w:r></w:p></w:body>"
        "</w:document>"
    ).encode("utf-8")
    content_types = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="xml" ContentType="application/xml"/>'
        "</Types>"
    ).encode("utf-8")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=compression) as archive:
        archive.writestr("[Content_Types].xml", content_types)
        archive.writestr("word/document.xml", document_xml)
        for name, value in extra_entries or []:
            archive.writestr(name, value)
    return buffer.getvalue()


def _mark_first_zip_entry_encrypted(payload: bytes) -> bytes:
    mutated = bytearray(payload)
    local_offset = mutated.find(b"PK\x03\x04")
    central_offset = mutated.find(b"PK\x01\x02")
    if local_offset < 0 or central_offset < 0:
        raise AssertionError("Synthetic ZIP did not contain expected headers")
    local_flags = int.from_bytes(mutated[local_offset + 6:local_offset + 8], "little") | 0x1
    central_flags = int.from_bytes(mutated[central_offset + 8:central_offset + 10], "little") | 0x1
    mutated[local_offset + 6:local_offset + 8] = local_flags.to_bytes(2, "little")
    mutated[central_offset + 8:central_offset + 10] = central_flags.to_bytes(2, "little")
    return bytes(mutated)


class PDFIngestionSafetyTests(unittest.TestCase):
    def extract_with(self, document: _FakePDFDocument):
        with patch("rag.pymupdf.open", return_value=document), patch.object(
            PDFProcessor, "_extract_pypdf_text", return_value=""
        ):
            return PDFProcessor.extract_text_and_metadata(b"synthetic-pdf")

    def test_normal_extraction_closes_document(self):
        document = _FakePDFDocument(["Observed domain body-only.example"])
        text, metadata = self.extract_with(document)
        self.assertTrue(document.closed)
        self.assertIn("body-only.example", text)
        self.assertEqual(metadata["pages"], 1)

    def test_page_character_and_encryption_bounds_close_document(self):
        cases = (
            ("page count", _FakePDFDocument(["one", "two"]), "MAX_PDF_PAGES", 1),
            (
                "character count",
                _FakePDFDocument(["x" * 100]),
                "MAX_PDF_EXTRACTED_CHARACTERS",
                50,
            ),
            ("encryption", _FakePDFDocument(["secret"], needs_pass=True), None, None),
        )
        for label, document, constant, limit in cases:
            with self.subTest(label=label):
                limit_patch = (
                    patch.object(PDFProcessor, constant, limit)
                    if constant
                    else patch.object(PDFProcessor, "MAX_PDF_PAGES", PDFProcessor.MAX_PDF_PAGES)
                )
                with limit_patch, self.assertRaises(DocumentSafetyError):
                    self.extract_with(document)
                self.assertTrue(document.closed)


class DOCXContainerSafetyTests(unittest.TestCase):
    def assert_rejected(self, payload: bytes, reason_fragment: str):
        valid, reason = DOCXProcessor.validate_container(payload)
        self.assertFalse(valid)
        self.assertIn(reason_fragment.lower(), reason.lower())

    def test_valid_minimal_docx_is_accepted(self):
        payload = _minimal_docx()
        valid, reason = DOCXProcessor.validate_container(payload)
        self.assertTrue(valid, reason)
        text, metadata = DOCXProcessor.extract_text_and_metadata(payload, "safe.docx")
        self.assertIn("safe.example", text)
        self.assertEqual(metadata["paragraph_count"], 1)

    def test_traversal_and_symlink_members_are_rejected(self):
        self.assert_rejected(_minimal_docx(extra_entries=[("../outside.txt", b"bad")]), "unsafe member path")

        link = zipfile.ZipInfo("word/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.assert_rejected(_minimal_docx(extra_entries=[(link, b"target")]), "symbolic link")

    def test_encrypted_entries_are_rejected(self):
        self.assert_rejected(_mark_first_zip_entry_encrypted(_minimal_docx()), "encrypted")

    def test_entry_count_expanded_size_and_compression_ratio_are_bounded(self):
        payload = _minimal_docx()
        with patch.object(DOCXProcessor, "MAX_DOCX_ENTRIES", 1):
            self.assert_rejected(payload, "entries")
        with patch.object(DOCXProcessor, "MAX_DOCX_UNCOMPRESSED_BYTES", 10):
            self.assert_rejected(payload, "expands beyond")

        compressed_payload = _minimal_docx(
            extra_entries=[("word/repeated.bin", b"A" * 100_000)],
            compression=zipfile.ZIP_DEFLATED,
        )
        self.assert_rejected(compressed_payload, "compression ratio")

    def test_document_validator_returns_the_container_reason(self):
        valid, reason = DocumentValidator.validate_file(
            "unsafe.docx",
            _minimal_docx(extra_entries=[("word/../../outside", b"bad")]),
        )
        self.assertFalse(valid)
        self.assertIn("unsafe member path", reason.lower())


class YAMLIngestionSafetyTests(unittest.TestCase):
    def test_ordinary_aliases_and_merge_keys_remain_supported(self):
        payload = b"""
defaults: &defaults
  severity: high
  observables:
    - c2.safe.example
report:
  <<: *defaults
  title: Ordinary anchored report
duplicate_observables: *defaults
"""
        text, metadata = YAMLProcessor.extract_text_and_metadata(payload, "summary.yaml")

        self.assertTrue(metadata["yaml_parser_available"])
        self.assertEqual(metadata["yaml_top_level_type"], "dict")
        self.assertIn("Ordinary anchored report", text)
        self.assertIn("c2.safe.example", text)

    def test_alias_amplification_is_rejected_before_construction(self):
        aliases = ", ".join(["*previous"] * 9)
        lines = ['level0: &previous ["bounded"]']
        for level in range(1, 7):
            anchor = f"level{level}"
            lines.append(f"{anchor}: &next{level} [{aliases}]")
            lines.append(f"next{level}: *next{level}")
            aliases = ", ".join([f"*next{level}"] * 9)
        payload = "\n".join(lines).encode("utf-8")

        with self.assertRaisesRegex(DocumentSafetyError, "Expanded YAML"):
            YAMLProcessor.extract_text_and_metadata(payload, "amplified.yaml")

    def test_cyclic_alias_is_rejected(self):
        with self.assertRaisesRegex(DocumentSafetyError, "cyclic alias"):
            YAMLProcessor.extract_text_and_metadata(b"loop: &loop [*loop]\n", "cycle.yaml")

    def test_parse_error_metadata_does_not_include_document_content(self):
        secret = "DO-NOT-EXPOSE-THIS-VALUE"
        payload = f"secret: {secret}\nbroken: [\n".encode("utf-8")

        text, metadata = YAMLProcessor.extract_text_and_metadata(payload, "invalid.yaml")

        self.assertIn(secret, text)
        self.assertIn("yaml_parse_error", metadata)
        self.assertNotIn(secret, metadata["yaml_parse_error"])


class ProcessedHashLifecycleTests(unittest.TestCase):
    def test_request_scoped_processing_does_not_poison_global_hash_state(self):
        payload = b"Observed domain request-scoped.example"
        with tempfile.TemporaryDirectory() as directory:
            processor = DocumentProcessor(directory)
            processor.process_upload(
                payload,
                "report.txt",
                save_to_disk=False,
                remember_processed=False,
            )
            self.assertFalse(processor.processed_hashes)
            self.assertFalse(processor.processing_hashes)

            # A downstream build could have failed; the next request may retry.
            processor.process_upload(
                payload,
                "renamed.txt",
                save_to_disk=False,
                remember_processed=False,
            )

    def test_default_behavior_still_remembers_successful_processing(self):
        payload = b"Observed domain remembered.example"
        with tempfile.TemporaryDirectory() as directory:
            processor = DocumentProcessor(directory)
            processor.process_upload(payload, "report.txt", save_to_disk=False)
            self.assertTrue(processor.processed_hashes)
            with self.assertRaisesRegex(ValueError, "already been processed"):
                processor.process_upload(payload, "renamed.txt", save_to_disk=False)


if __name__ == "__main__":
    unittest.main()
