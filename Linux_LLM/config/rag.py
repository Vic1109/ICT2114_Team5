import io
from contextlib import closing
from pathlib import Path
from typing import List, Dict, Tuple, Any, Optional
from datetime import datetime
from html.parser import HTMLParser
try:
    import pymupdf  # PyMuPDF >= 1.24
except ImportError:  # pragma: no cover - depends on deployment package version
    import fitz as pymupdf  # PyMuPDF legacy import name
import csv
import hashlib
import html
import json
import re
import stat
import threading
import zipfile
import xml.etree.ElementTree as ET
from urllib.parse import urlparse
from cti_artifacts import CTIArtifactExtractor
from runtime_utils import atomic_write_text, configure_console_encoding, log_sanitized_exception


configure_console_encoding()


class DocumentSafetyError(ValueError):
    """Raised when a document exceeds a deterministic ingestion safety bound."""


class PDFProcessor:
    """Handles PDF document text extraction"""
    MAX_PDF_PAGES = 1_000
    MAX_PDF_EXTRACTED_CHARACTERS = 5_000_000
    MAX_PDF_METADATA_CHARACTERS = 4_096
    TABLE_HINT_RE = re.compile(
        r"\b(?:ioc|indicator|indicators|hash|md5|sha1|sha256|ip address|domain|url|uri|"
        r"cve|mitre|technique|ttp|table)\b",
        re.IGNORECASE,
    )
    LINK_HINT_RE = re.compile(
        r"\b(?:ioc|indicator|indicators|malicious|c2|c&c|command and control|"
        r"payload|dropper|callback|beacon|exploit|phish|ransomware|hash|md5|"
        r"sha1|sha256|domain|url|uri|ip address)\b",
        re.IGNORECASE,
    )
    LINK_INDICATOR_RE = re.compile(
        r"(?:\b(?:\d{1,3}\.){3}\d{1,3}\b|[A-Fa-f0-9]{32,64}|"
        r"\.(?:exe|dll|vbs|js|jse|ps1|bat|cmd|hta|scr|msi|zip|7z|rar)(?:$|[/?#]))",
        re.IGNORECASE,
    )
    COMMON_REFERENCE_LINK_DOMAINS = {
        "www.w3.org", "w3.org", "schema.org", "www.schema.org",
        "fonts.googleapis.com", "fonts.gstatic.com", "www.google-analytics.com",
        "google-analytics.com", "www.googletagmanager.com", "googletagmanager.com",
        "ajax.googleapis.com", "cdnjs.cloudflare.com",
    }
    
    @staticmethod
    def extract_text(file_content: bytes) -> str:
        """Extract text with selective table detection"""
        text, _metadata = PDFProcessor.extract_text_and_metadata(file_content)
        return text

    @staticmethod
    def extract_text_and_metadata(file_content: bytes) -> Tuple[str, Dict[str, Any]]:
        """Extract PDF text and metadata while opening the document only once."""
        try:
            pdf_stream = io.BytesIO(file_content)
            with closing(pymupdf.open(stream=pdf_stream, filetype="pdf")) as doc:
                PDFProcessor._validate_pdf_document(doc)
                page_count = len(doc)
                doc_metadata = getattr(doc, "metadata", None) or {}
                full_text = []
                extracted_characters = 0
                metadata = {
                    'pages': page_count,
                    'title': PDFProcessor._bounded_metadata(doc_metadata.get('title', '')),
                    'author': PDFProcessor._bounded_metadata(doc_metadata.get('author', '')),
                    'subject': PDFProcessor._bounded_metadata(doc_metadata.get('subject', '')),
                    'creator': PDFProcessor._bounded_metadata(doc_metadata.get('creator', '')),
                    'producer': PDFProcessor._bounded_metadata(doc_metadata.get('producer', '')),
                    'creation_date': PDFProcessor._bounded_metadata(doc_metadata.get('creationDate', '')),
                    'modification_date': PDFProcessor._bounded_metadata(doc_metadata.get('modDate', '')),
                }

                for page_num in range(page_count):
                    page = doc[page_num]

                    extracted_text = page.get_text("text", sort=True).strip()
                    page_parts = [f"\n--- Page {page_num + 1} ---\n"]
                    if extracted_text:
                        page_parts.append(extracted_text)

                    # Table detection is expensive. Plain text extraction normally
                    # captures table cell values, so only add markdown table structure
                    # for pages that look like CTI/IoC tables.
                    if PDFProcessor._should_extract_tables(extracted_text):
                        try:
                            tables = page.find_tables()
                            if tables:
                                page_parts.append("\n[TABLES DETECTED]")
                                for table in tables:
                                    table_markdown = table.to_markdown()
                                    if table_markdown.strip():
                                        page_parts.append(table_markdown)
                        except Exception as table_error:
                            print(
                                "WARNING: Table extraction skipped "
                                f"(page={page_num + 1}, error={type(table_error).__name__})"
                            )

                    links = [
                        link["uri"] for link in page.get_links()
                        if "uri" in link and PDFProcessor._should_include_link(link["uri"], extracted_text)
                    ]
                    if links:
                        page_parts.append("\n[LINKS DETECTED]")
                        page_parts.extend(links)

                    image_count = len(page.get_images())
                    if image_count:
                        page_parts.append(
                            f"\n[IMAGES DETECTED: {image_count} image(s) on this page; OCR not performed]"
                        )

                    page_text = "\n".join(page_parts)
                    extracted_characters += len(page_text)
                    PDFProcessor._validate_character_count(extracted_characters)
                    full_text.append(page_text)

            primary_text = "\n".join(full_text)
            fallback_text = PDFProcessor._extract_pypdf_text(file_content)
            merged_text, fallback_metadata = PDFProcessor._merge_fallback_text_if_useful(
                primary_text,
                fallback_text,
                pages=metadata.get("pages", 0),
            )
            PDFProcessor._validate_character_count(len(merged_text))
            metadata.update(fallback_metadata)
            return merged_text, metadata
        except DocumentSafetyError:
            raise
        except Exception as e:
            log_sanitized_exception("PDF extraction failed", e)
            fallback_text = PDFProcessor._extract_pypdf_text(file_content)
            if fallback_text.strip():
                return fallback_text, {
                    "pages": 0,
                    "fallback_extractor": "pypdf",
                    "fallback_available": True,
                    "fallback_used": True,
                    "fallback_reason": "pymupdf_failed",
                    "fallback_characters": len(fallback_text),
                }
            return "", {'pages': 0}

    @classmethod
    def _validate_pdf_document(cls, doc: Any) -> None:
        if bool(getattr(doc, "needs_pass", False)):
            raise DocumentSafetyError("Encrypted or password-protected PDF files are not supported")
        page_count = len(doc)
        if page_count > cls.MAX_PDF_PAGES:
            raise DocumentSafetyError(
                f"PDF contains {page_count} pages; maximum allowed is {cls.MAX_PDF_PAGES}"
            )

    @classmethod
    def _validate_character_count(cls, character_count: int) -> None:
        if character_count > cls.MAX_PDF_EXTRACTED_CHARACTERS:
            raise DocumentSafetyError(
                "PDF extracted text exceeds the maximum allowed character count "
                f"({cls.MAX_PDF_EXTRACTED_CHARACTERS})"
            )

    @classmethod
    def _bounded_metadata(cls, value: Any) -> str:
        return str(value or "")[:cls.MAX_PDF_METADATA_CHARACTERS]

    @staticmethod
    def _should_extract_tables(page_text: str) -> bool:
        if not page_text:
            return False
        if not PDFProcessor.TABLE_HINT_RE.search(page_text):
            return False
        lines = [line for line in page_text.splitlines() if line.strip()]
        aligned_lines = sum(1 for line in lines if "\t" in line or re.search(r"\S\s{2,}\S", line))
        delimiter_lines = sum(1 for line in lines if line.count("|") >= 2 or line.count(",") >= 3)
        return aligned_lines >= 2 or delimiter_lines >= 2

    @staticmethod
    def _should_include_link(uri: str, page_text: str) -> bool:
        """Keep PDF annotation links only when they look analytically useful."""
        uri = str(uri or "").strip()
        if not uri:
            return False

        try:
            host = (urlparse(uri).hostname or "").lower()
        except ValueError:
            host = ""
        if host in PDFProcessor.COMMON_REFERENCE_LINK_DOMAINS:
            return False

        if PDFProcessor.LINK_INDICATOR_RE.search(uri):
            return True

        page_text = str(page_text or "")
        if PDFProcessor.LINK_HINT_RE.search(page_text):
            return True

        return False

    @staticmethod
    def _extract_pypdf_text(file_content: bytes) -> str:
        """Best-effort secondary extraction for PDFs PyMuPDF handles poorly."""
        try:
            from pypdf import PdfReader
        except Exception:
            return ""

        try:
            reader = PdfReader(io.BytesIO(file_content), strict=False)
            if bool(getattr(reader, "is_encrypted", False)):
                raise DocumentSafetyError("Encrypted or password-protected PDF files are not supported")
            page_count = len(reader.pages)
            if page_count > PDFProcessor.MAX_PDF_PAGES:
                raise DocumentSafetyError(
                    f"PDF contains {page_count} pages; maximum allowed is {PDFProcessor.MAX_PDF_PAGES}"
                )
            parts = []
            extracted_characters = 0
            for page_num, page in enumerate(reader.pages):
                try:
                    page_text = page.extract_text() or ""
                except Exception:
                    page_text = ""
                page_text = page_text.strip()
                if page_text:
                    part = f"\n--- PYPDF Fallback Page {page_num + 1} ---\n{page_text}"
                    extracted_characters += len(part)
                    PDFProcessor._validate_character_count(extracted_characters)
                    parts.append(part)
            return "\n".join(parts)
        except DocumentSafetyError:
            raise
        except Exception as error:
            log_sanitized_exception("pypdf fallback extraction skipped", error)
            return ""

    @staticmethod
    def _merge_fallback_text_if_useful(primary_text: str, fallback_text: str, pages: int = 0) -> Tuple[str, Dict[str, Any]]:
        primary_text = str(primary_text or "")
        fallback_text = str(fallback_text or "")
        metadata = {
            "fallback_extractor": "pypdf",
            "fallback_available": bool(fallback_text.strip()),
            "fallback_used": False,
            "fallback_characters": len(fallback_text),
        }
        if not fallback_text.strip():
            return primary_text, metadata

        primary_artifacts = CTIArtifactExtractor.for_cti_context(
            CTIArtifactExtractor.extract(primary_text)
        )
        fallback_artifacts = CTIArtifactExtractor.for_cti_context(
            CTIArtifactExtractor.extract(fallback_text)
        )
        added_artifacts = {}
        for key, fallback_values in fallback_artifacts.items():
            primary_values = {
                str(value).lower()
                for value in primary_artifacts.get(key, [])
                if value
            }
            added = [
                str(value)
                for value in fallback_values or []
                if str(value).lower() not in primary_values
            ]
            if added:
                added_artifacts[key] = added[:20]

        page_count = max(0, int(pages or 0))
        primary_chars_per_page = int(len(primary_text) / page_count) if page_count else len(primary_text)
        use_fallback = bool(added_artifacts) or (
            primary_chars_per_page < 250 and len(fallback_text) > len(primary_text) * 1.2
        )

        if not use_fallback:
            return primary_text, metadata

        fallback_reason = "additional_cti_artifacts" if added_artifacts else "low_primary_text_density"
        metadata.update({
            "fallback_used": True,
            "fallback_reason": fallback_reason,
            "fallback_added_artifacts": CTIArtifactExtractor.count_by_type(added_artifacts),
        })
        if fallback_reason == "additional_cti_artifacts" and primary_chars_per_page >= 250:
            recovered_artifact_line = CTIArtifactExtractor.format_for_context(
                added_artifacts,
                max_items_per_type=40,
            )
            fallback_section = (
                "[SECONDARY PDF EXTRACTION - recovered CTI artifacts]\n"
                f"{recovered_artifact_line}"
            )
        else:
            fallback_section = f"[SECONDARY PDF EXTRACTION - pypdf]\n{fallback_text}"

        merged_text = (
            f"{primary_text}\n\n{fallback_section}"
            if primary_text.strip()
            else fallback_section
        )
        return merged_text, metadata
    
class TextProcessor:
    """Handles plain text file processing"""
    
    @staticmethod
    def extract_text(file_content: bytes, encoding: str = 'utf-8') -> str:
        """Extract text from plain text files"""
        try:
            return file_content.decode(encoding, errors='ignore').strip()
        except Exception as e:
            log_sanitized_exception("Text extraction failed", e)
            return ""
    
    @staticmethod
    def detect_encoding(file_content: bytes) -> str:
        """Simple encoding detection"""
        try:
            # Try common encodings
            encodings = ['utf-8', 'utf-16', 'latin-1', 'cp1252']
            
            for encoding in encodings:
                try:
                    file_content.decode(encoding)
                    return encoding
                except UnicodeDecodeError:
                    continue
            
            return 'utf-8'  # Fallback
        except Exception:
            return 'utf-8'


class MarkdownProcessor:
    """Handles Markdown file processing"""
    
    @staticmethod
    def extract_text(file_content: bytes, preserve_structure: bool = True) -> str:
        """Extract text from Markdown files"""
        try:
            text = file_content.decode('utf-8', errors='ignore')
            
            if not preserve_structure:
                # Strip basic markdown formatting for plain text
                import re
                # Remove headers
                text = re.sub(r'^#{1,6}\s+', '', text, flags=re.MULTILINE)
                # Remove bold/italic
                text = re.sub(r'\*\*([^*]+)\*\*', r'\1', text)
                text = re.sub(r'\*([^*]+)\*', r'\1', text)
                # Remove links but keep text
                text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
                # Remove code blocks
                text = re.sub(r'```[^`]*```', '', text, flags=re.DOTALL)
                text = re.sub(r'`([^`]+)`', r'\1', text)
            
            return text.strip()
        except Exception as e:
            log_sanitized_exception("Markdown extraction failed", e)
            return ""


class JSONProcessor:
    """Handles structured CTI summary JSON files."""

    FIELD_ORDER = [
        "report_id",
        "title",
        "severity",
        "summary",
        "aliases",
        "targets",
        "key_findings",
        "observables",
        "mitre_attack",
        "attack_flow",
        "recommended_actions",
    ]

    @staticmethod
    def extract_text_and_metadata(file_content: bytes, filename: str = "") -> Tuple[str, Dict[str, Any]]:
        """Convert JSON CTI summaries into retrieval-friendly text."""
        raw_text = None
        for encoding in ("utf-8-sig", "utf-8", "latin-1", "cp1252"):
            try:
                raw_text = file_content.decode(encoding)
                break
            except UnicodeDecodeError:
                continue

        if raw_text is None:
            raise ValueError(f"Unable to decode JSON file {filename}")

        try:
            parsed = json.loads(raw_text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSON in {filename}: {exc}") from exc

        text = JSONProcessor._format_for_rag(parsed, filename)
        structured_artifacts = CTIArtifactExtractor.extract_structured(parsed)
        metadata = {
            "filename": filename,
            "type": "json",
            "characters": len(text),
            "processed_at": datetime.now().isoformat(),
            "json_top_level_type": type(parsed).__name__,
        }
        if structured_artifacts:
            metadata["structured_cti_artifacts"] = structured_artifacts
            metadata["structured_artifact_counts"] = CTIArtifactExtractor.count_by_type(structured_artifacts)
        if isinstance(parsed, dict):
            metadata["json_keys"] = list(parsed.keys())
            stix_type = str(parsed.get("type") or "").strip()
            if stix_type:
                metadata["stix_type"] = stix_type
            if stix_type == "bundle" and isinstance(parsed.get("objects"), list):
                metadata["stix_object_count"] = len(parsed.get("objects") or [])
            if parsed.get("report_id"):
                metadata["report_id"] = str(parsed["report_id"])
            if parsed.get("title"):
                metadata["json_title"] = str(parsed["title"])
            elif parsed.get("name"):
                metadata["json_title"] = str(parsed["name"])
            if parsed.get("severity"):
                metadata["severity"] = str(parsed["severity"])

        return text, metadata

    @staticmethod
    def _format_for_rag(data: Any, filename: str) -> str:
        sections = [
            "CTI Structured Summary",
        ]
        stix_summary = JSONProcessor._format_stix_summary(data)
        if stix_summary:
            sections.append("\n## STIX Relationship Summary")
            sections.append(stix_summary)

        if isinstance(data, dict):
            for key in JSONProcessor.FIELD_ORDER:
                if key not in data:
                    continue
                sections.append(f"\n## {JSONProcessor._title(key)}")
                sections.append(JSONProcessor._format_value(data[key]))

            remaining = {
                key: value for key, value in data.items()
                if key not in JSONProcessor.FIELD_ORDER
            }
            if remaining:
                sections.append("\n## Additional Structured Fields")
                sections.append(JSONProcessor._format_value(remaining))
        else:
            sections.append("\n## Structured Data")
            sections.append(JSONProcessor._format_value(data))

        sections.append("\n## Raw JSON")
        sections.append(json.dumps(data, ensure_ascii=False, indent=2))
        return "\n".join(part for part in sections if part).strip()

    @staticmethod
    def _format_stix_summary(data: Any) -> str:
        if not isinstance(data, dict):
            return ""
        objects = data.get("objects") if data.get("type") == "bundle" else [data]
        if not isinstance(objects, list):
            return ""

        object_by_id = {
            str(item.get("id")): item
            for item in objects
            if isinstance(item, dict) and item.get("id")
        }

        def label(item_id: Any) -> str:
            item = object_by_id.get(str(item_id))
            if not isinstance(item, dict):
                return str(item_id or "")
            name = item.get("name") or item.get("value") or item.get("pattern") or item.get("id")
            item_type = item.get("type")
            return f"{name} ({item_type})" if item_type and name else str(name or "")

        lines = []
        for item in objects:
            if not isinstance(item, dict):
                continue
            object_type = str(item.get("type") or "")
            name = item.get("name") or item.get("value")
            aliases = item.get("aliases")
            if object_type in {
                "threat-actor",
                "intrusion-set",
                "malware",
                "campaign",
                "tool",
                "course-of-action",
                "attack-pattern",
                "vulnerability",
            } and name:
                alias_text = ""
                if isinstance(aliases, list) and aliases:
                    alias_text = " aliases=" + ", ".join(str(alias) for alias in aliases[:8])
                lines.append(f"- STIX {object_type}: {name}{alias_text}")

            if object_type == "relationship":
                source = label(item.get("source_ref"))
                target = label(item.get("target_ref"))
                relationship_type = item.get("relationship_type") or "related-to"
                if source and target:
                    lines.append(f"- STIX relationship: {source} {relationship_type} {target}")

        return "\n".join(lines[:80])

    @staticmethod
    def _format_value(value: Any, indent: int = 0) -> str:
        prefix = "  " * indent
        if isinstance(value, dict):
            lines = []
            for key, child in value.items():
                if isinstance(child, (dict, list)):
                    lines.append(f"{prefix}{JSONProcessor._title(str(key))}:")
                    lines.append(JSONProcessor._format_value(child, indent + 1))
                else:
                    lines.append(f"{prefix}{JSONProcessor._title(str(key))}: {child}")
            return "\n".join(lines)

        if isinstance(value, list):
            lines = []
            for item in value:
                if isinstance(item, (dict, list)):
                    lines.append(f"{prefix}-")
                    lines.append(JSONProcessor._format_value(item, indent + 1))
                else:
                    lines.append(f"{prefix}- {item}")
            return "\n".join(lines)

        return f"{prefix}{value}"

    @staticmethod
    def _title(key: str) -> str:
        return key.replace("_", " ").strip().title()


class HTMLProcessor:
    """Extract CTI article text from saved HTML pages without external parsers."""

    class _ReadableHTMLParser(HTMLParser):
        SKIP_TAGS = {"script", "style", "noscript", "svg", "canvas"}
        BLOCK_TAGS = {
            "address", "article", "aside", "blockquote", "br", "caption", "dd",
            "div", "dl", "dt", "figcaption", "figure", "footer", "h1", "h2",
            "h3", "h4", "h5", "h6", "header", "hr", "li", "main", "nav", "p",
            "pre", "section", "table", "tbody", "td", "tfoot", "th", "thead",
            "tr", "ul", "ol",
        }

        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.parts: List[str] = []
            self.links: List[str] = []
            self._skip_depth = 0
            self._title_depth = 0
            self.title_parts: List[str] = []

        def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
            tag = tag.lower()
            if tag in self.SKIP_TAGS:
                self._skip_depth += 1
                return
            if tag == "title":
                self._title_depth += 1
            if tag == "a":
                href = dict(attrs).get("href")
                if href:
                    self.links.append(html.unescape(str(href)).strip())
            if tag in self.BLOCK_TAGS:
                self.parts.append("\n")

        def handle_endtag(self, tag: str):
            tag = tag.lower()
            if tag in self.SKIP_TAGS and self._skip_depth:
                self._skip_depth -= 1
                return
            if tag == "title" and self._title_depth:
                self._title_depth -= 1
            if tag in self.BLOCK_TAGS:
                self.parts.append("\n")

        def handle_data(self, data: str):
            if self._skip_depth:
                return
            text = html.unescape(data or "")
            if self._title_depth:
                self.title_parts.append(text)
            self.parts.append(text)

        def readable_text(self) -> str:
            text = "".join(self.parts)
            text = re.sub(r"[ \t\r\f\v]+", " ", text)
            text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)
            return text.strip()

        def title(self) -> str:
            return re.sub(r"\s+", " ", "".join(self.title_parts)).strip()

    @staticmethod
    def extract_text_and_metadata(file_content: bytes, filename: str = "") -> Tuple[str, Dict[str, Any]]:
        text = TextProcessor.extract_text(file_content, TextProcessor.detect_encoding(file_content))
        parser = HTMLProcessor._ReadableHTMLParser()
        try:
            parser.feed(text)
            parser.close()
        except Exception as exc:
            log_sanitized_exception("HTML parser recovered partial text", exc)

        readable = parser.readable_text()
        links = [
            link for link in CTIArtifactExtractor._unique(parser.links)
            if link and not link.lower().startswith(("javascript:", "mailto:"))
        ]
        if links:
            readable = f"{readable}\n\n[LINKS DETECTED]\n" + "\n".join(links)

        metadata = {
            "filename": filename,
            "type": "html",
            "characters": len(readable),
            "processed_at": datetime.now().isoformat(),
        }
        title = parser.title()
        if title:
            metadata["html_title"] = title
        if links:
            metadata["link_count"] = len(links)
        return readable, metadata


class CSVProcessor:
    """Convert CSV/TSV IoC exports into retrieval-friendly text."""

    @staticmethod
    def extract_text_and_metadata(file_content: bytes, filename: str = "") -> Tuple[str, Dict[str, Any]]:
        raw_text = TextProcessor.extract_text(file_content, TextProcessor.detect_encoding(file_content))
        sample = raw_text[:4096]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
        except csv.Error:
            dialect = csv.excel_tab if Path(filename).suffix.lower() == ".tsv" else csv.excel

        rows = []
        reader = csv.reader(io.StringIO(raw_text), dialect)
        for index, row in enumerate(reader):
            if index >= 1000:
                break
            cleaned = [str(cell).strip() for cell in row]
            if any(cleaned):
                rows.append(cleaned)

        if not rows:
            return raw_text, {
                "filename": filename,
                "type": "csv",
                "characters": len(raw_text),
                "processed_at": datetime.now().isoformat(),
                "row_count": 0,
            }

        width = max(len(row) for row in rows)
        padded_rows = [row + [""] * (width - len(row)) for row in rows]
        headers = padded_rows[0]
        generic_headers = all(not value for value in headers)
        if generic_headers:
            headers = [f"Column {i + 1}" for i in range(width)]
            data_rows = padded_rows
        else:
            data_rows = padded_rows[1:]

        lines = ["CTI Tabular Data"]
        lines.append("\n## Columns")
        lines.append(", ".join(headers))
        lines.append("\n## Rows")
        for row in data_rows[:999]:
            pairs = [
                f"{headers[i] or f'Column {i + 1}'}: {value}"
                for i, value in enumerate(row)
                if value
            ]
            if pairs:
                lines.append("- " + " | ".join(pairs))

        text = "\n".join(line for line in lines if line).strip()
        return text, {
            "filename": filename,
            "type": "csv",
            "characters": len(text),
            "processed_at": datetime.now().isoformat(),
            "row_count": len(rows),
            "column_count": width,
        }


class YAMLProcessor:
    """Handle YAML CTI summaries when PyYAML is available, otherwise preserve text."""

    # YAML aliases share objects in PyYAML's constructed graph, but downstream
    # formatting walks every reference. Bound the composed and expanded graphs
    # before construction so a small alias document cannot amplify into an
    # unbounded traversal. The scalar budget matches the 5 MiB YAML upload cap.
    MAX_YAML_ALIASES = 1_000
    MAX_YAML_COMPOSED_NODES = 100_000
    MAX_YAML_NESTING_DEPTH = 100
    MAX_YAML_EXPANDED_NODES = 100_000
    MAX_YAML_EXPANDED_SCALAR_CHARACTERS = 5 * 1024 * 1024

    @classmethod
    def _safe_load_bounded(cls, raw_text: str, yaml_module: Any) -> Any:
        processor_class = cls

        class BoundedSafeLoader(yaml_module.SafeLoader):
            def __init__(self, stream: str):
                super().__init__(stream)
                self.yaml_alias_count = 0
                self.yaml_composed_node_count = 0
                self.yaml_nesting_depth = 0

            def compose_node(self, parent: Any, index: Any) -> Any:
                is_alias = self.check_event(yaml_module.events.AliasEvent)
                if is_alias:
                    self.yaml_alias_count += 1
                    if self.yaml_alias_count > processor_class.MAX_YAML_ALIASES:
                        raise DocumentSafetyError("YAML contains too many aliases")
                else:
                    self.yaml_composed_node_count += 1
                    if self.yaml_composed_node_count > processor_class.MAX_YAML_COMPOSED_NODES:
                        raise DocumentSafetyError("YAML contains too many composed nodes")

                self.yaml_nesting_depth += 1
                try:
                    if self.yaml_nesting_depth > processor_class.MAX_YAML_NESTING_DEPTH:
                        raise DocumentSafetyError("YAML nesting exceeds the maximum allowed depth")
                    return super().compose_node(parent, index)
                finally:
                    self.yaml_nesting_depth -= 1

        loader = BoundedSafeLoader(raw_text)
        try:
            node = loader.get_single_node()
            if node is None:
                return None
            cls._validate_expanded_graph(node, yaml_module)
            return loader.construct_document(node)
        finally:
            loader.dispose()

    @classmethod
    def _validate_expanded_graph(cls, root: Any, yaml_module: Any) -> None:
        """Walk alias references as downstream formatters will, within hard budgets."""
        expanded_nodes = 0
        expanded_scalar_characters = 0
        active_node_ids = set()
        stack = [(root, False)]

        while stack:
            node, exiting = stack.pop()
            node_id = id(node)
            if exiting:
                active_node_ids.remove(node_id)
                continue

            if node_id in active_node_ids:
                raise DocumentSafetyError("YAML contains a cyclic alias")

            expanded_nodes += 1
            if expanded_nodes > cls.MAX_YAML_EXPANDED_NODES:
                raise DocumentSafetyError("Expanded YAML exceeds the maximum allowed node count")

            if isinstance(node, yaml_module.nodes.ScalarNode):
                expanded_scalar_characters += len(str(node.value or ""))
                if expanded_scalar_characters > cls.MAX_YAML_EXPANDED_SCALAR_CHARACTERS:
                    raise DocumentSafetyError(
                        "Expanded YAML exceeds the maximum allowed scalar character count"
                    )
                continue

            if isinstance(node, yaml_module.nodes.SequenceNode):
                children = list(node.value)
            elif isinstance(node, yaml_module.nodes.MappingNode):
                children = [child for pair in node.value for child in pair]
            else:  # SafeLoader should only compose scalar, sequence, and mapping nodes.
                raise DocumentSafetyError("YAML contains an unsupported node type")

            active_node_ids.add(node_id)
            stack.append((node, True))
            stack.extend((child, False) for child in reversed(children))

    @classmethod
    def extract_text_and_metadata(cls, file_content: bytes, filename: str = "") -> Tuple[str, Dict[str, Any]]:
        raw_text = TextProcessor.extract_text(file_content, TextProcessor.detect_encoding(file_content))
        metadata = {
            "filename": filename,
            "type": "yaml",
            "characters": len(raw_text),
            "processed_at": datetime.now().isoformat(),
            "yaml_parser_available": False,
        }

        try:
            import yaml  # type: ignore
        except Exception:
            return raw_text, metadata

        try:
            parsed = cls._safe_load_bounded(raw_text, yaml)
        except DocumentSafetyError:
            raise
        except Exception as exc:
            metadata["yaml_parse_error"] = type(exc).__name__
            return raw_text, metadata

        metadata["yaml_parser_available"] = True
        metadata["yaml_top_level_type"] = type(parsed).__name__
        text = JSONProcessor._format_for_rag(parsed, filename)
        metadata["characters"] = len(text)
        structured_artifacts = CTIArtifactExtractor.extract_structured(parsed)
        if structured_artifacts:
            metadata["structured_cti_artifacts"] = structured_artifacts
            metadata["structured_artifact_counts"] = CTIArtifactExtractor.count_by_type(structured_artifacts)
        return text, metadata


class XMLProcessor:
    """Extract readable text and attributes from XML/STIX 1.x style documents."""

    @staticmethod
    def extract_text_and_metadata(file_content: bytes, filename: str = "") -> Tuple[str, Dict[str, Any]]:
        raw_text = TextProcessor.extract_text(file_content, TextProcessor.detect_encoding(file_content))
        try:
            root = ET.fromstring(raw_text)
        except ET.ParseError as exc:
            return raw_text, {
                "filename": filename,
                "type": "xml",
                "characters": len(raw_text),
                "processed_at": datetime.now().isoformat(),
                "xml_parse_error": type(exc).__name__,
            }

        lines = ["CTI XML Document"]
        element_count = 0
        for element in root.iter():
            element_count += 1
            if element_count > 5000:
                break
            tag = XMLProcessor._strip_namespace(element.tag)
            attrs = " ".join(
                f"{XMLProcessor._strip_namespace(key)}={value}"
                for key, value in element.attrib.items()
                if value
            )
            text = re.sub(r"\s+", " ", "".join(element.itertext())).strip()
            if attrs or text:
                line = f"{tag}:"
                if attrs:
                    line += f" {attrs}"
                if text:
                    line += f" {text[:1000]}"
                lines.append(line)

        text = "\n".join(line for line in lines if line).strip()
        return text, {
            "filename": filename,
            "type": "xml",
            "characters": len(text),
            "processed_at": datetime.now().isoformat(),
            "xml_root": XMLProcessor._strip_namespace(root.tag),
            "xml_element_count": element_count,
        }

    @staticmethod
    def _strip_namespace(value: Any) -> str:
        text = str(value or "")
        return text.rsplit("}", 1)[-1] if "}" in text else text


class DOCXProcessor:
    """Extract paragraphs/tables from non-macro DOCX CTI reports."""

    MAX_DOCX_UNCOMPRESSED_BYTES = 25 * 1024 * 1024
    MAX_DOCX_ENTRIES = 500
    MAX_DOCX_ENTRY_COMPRESSION_RATIO = 200.0
    MAX_DOCX_TOTAL_COMPRESSION_RATIO = 150.0
    MAX_DOCX_EXTRACTED_CHARACTERS = 5_000_000
    ALLOWED_COMPRESSION_METHODS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}

    @staticmethod
    def _normalized_member_name(name: str) -> str:
        return str(name or "").replace("\\", "/")

    @classmethod
    def validate_container(cls, file_content: bytes) -> Tuple[bool, str]:
        """Validate the bounded ZIP container used by an OOXML document."""
        try:
            with zipfile.ZipFile(io.BytesIO(file_content)) as archive:
                infos = archive.infolist()
                if len(infos) > cls.MAX_DOCX_ENTRIES:
                    return False, f"archive contains more than {cls.MAX_DOCX_ENTRIES} entries"

                total_uncompressed = 0
                total_compressed = 0
                normalized_names = set()
                casefold_names = set()

                for info in infos:
                    raw_name = str(info.filename or "")
                    normalized_name = cls._normalized_member_name(raw_name)
                    member_path = Path(normalized_name)
                    if (
                        not normalized_name
                        or "\x00" in normalized_name
                        or normalized_name.startswith("/")
                        or re.match(r"^[A-Za-z]:/", normalized_name)
                        or ".." in member_path.parts
                    ):
                        return False, f"archive contains an unsafe member path: {raw_name!r}"

                    casefold_name = normalized_name.casefold()
                    if casefold_name in casefold_names:
                        return False, f"archive contains a duplicate member path: {raw_name!r}"
                    casefold_names.add(casefold_name)
                    normalized_names.add(normalized_name)

                    if info.flag_bits & 0x1:
                        return False, f"archive member is encrypted: {raw_name!r}"
                    if info.compress_type not in cls.ALLOWED_COMPRESSION_METHODS:
                        return False, f"archive member uses an unsupported compression method: {raw_name!r}"

                    unix_mode = (info.external_attr >> 16) & 0xFFFF
                    if unix_mode and stat.S_ISLNK(unix_mode):
                        return False, f"archive contains a symbolic link: {raw_name!r}"

                    if info.file_size < 0 or info.compress_size < 0:
                        return False, f"archive member has invalid size metadata: {raw_name!r}"
                    total_uncompressed += info.file_size
                    total_compressed += info.compress_size
                    if total_uncompressed > cls.MAX_DOCX_UNCOMPRESSED_BYTES:
                        return False, (
                            "archive expands beyond the maximum allowed size "
                            f"({cls.MAX_DOCX_UNCOMPRESSED_BYTES} bytes)"
                        )

                    if info.file_size > 0:
                        if info.compress_size <= 0:
                            return False, f"archive member has an invalid compressed size: {raw_name!r}"
                        ratio = info.file_size / info.compress_size
                        if ratio > cls.MAX_DOCX_ENTRY_COMPRESSION_RATIO:
                            return False, (
                                f"archive member compression ratio is too high: {raw_name!r} "
                                f"({ratio:.1f}:1)"
                            )

                if total_uncompressed > 0:
                    if total_compressed <= 0:
                        return False, "archive has an invalid total compressed size"
                    total_ratio = total_uncompressed / total_compressed
                    if total_ratio > cls.MAX_DOCX_TOTAL_COMPRESSION_RATIO:
                        return False, f"archive compression ratio is too high ({total_ratio:.1f}:1)"

                required_names = {"[Content_Types].xml", "word/document.xml"}
                if not required_names.issubset(normalized_names):
                    return False, "archive is missing required DOCX members"
                if "word/vbaproject.bin" in casefold_names:
                    return False, "macro-enabled DOCX content is not supported"

                corrupt_member = archive.testzip()
                if corrupt_member:
                    return False, f"archive member failed its CRC check: {corrupt_member!r}"
                return True, "DOCX container validation passed"
        except (zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError, OSError) as error:
            return False, f"invalid DOCX ZIP container: {error}"

    @classmethod
    def is_safe_docx_container(cls, file_content: bytes) -> bool:
        valid, _reason = cls.validate_container(file_content)
        return valid

    @classmethod
    def extract_text_and_metadata(cls, file_content: bytes, filename: str = "") -> Tuple[str, Dict[str, Any]]:
        valid, reason = cls.validate_container(file_content)
        if not valid:
            raise DocumentSafetyError(f"Invalid or unsafe DOCX file {filename}: {reason}")

        with zipfile.ZipFile(io.BytesIO(file_content)) as archive:
            document_xml = archive.read("word/document.xml")

        try:
            root = ET.fromstring(document_xml)
        except ET.ParseError as error:
            raise DocumentSafetyError(f"Malformed DOCX document XML in {filename}: {error}") from error
        namespace = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
        paragraphs = []
        extracted_characters = 0
        for paragraph in root.findall(".//w:p", namespace):
            texts = [node.text or "" for node in paragraph.findall(".//w:t", namespace)]
            line = "".join(texts).strip()
            if line:
                extracted_characters += len(line) + (1 if paragraphs else 0)
                if extracted_characters > cls.MAX_DOCX_EXTRACTED_CHARACTERS:
                    raise DocumentSafetyError(
                        "DOCX extracted text exceeds the maximum allowed character count "
                        f"({cls.MAX_DOCX_EXTRACTED_CHARACTERS})"
                    )
                paragraphs.append(line)

        text = "\n".join(paragraphs).strip()
        return text, {
            "filename": filename,
            "type": "docx",
            "characters": len(text),
            "processed_at": datetime.now().isoformat(),
            "paragraph_count": len(paragraphs),
        }


class DocumentValidator:
    """Validates documents for security and content quality"""
    
    # Supported file types and their max sizes (in MB)
    SUPPORTED_TYPES = {
        '.pdf': 25,
        '.docx': 10,
        '.txt': 5,
        '.md': 5,
        '.markdown': 5,
        '.html': 5,
        '.htm': 5,
        '.csv': 5,
        '.tsv': 5,
        '.json': 5,
        '.stix': 5,
        '.yaml': 5,
        '.yml': 5,
        '.xml': 5
    }

    @staticmethod
    def max_size_bytes(filename: str) -> Optional[int]:
        file_ext = Path(filename).suffix.lower()
        max_size_mb = DocumentValidator.SUPPORTED_TYPES.get(file_ext)
        if max_size_mb is None:
            return None
        return max_size_mb * 1024 * 1024
    
    @staticmethod
    def validate_file(filename: str, file_content: bytes) -> Tuple[bool, str]:
        """Validate file type, size, and basic security checks"""
        try:
            file_path = Path(filename)
            file_ext = file_path.suffix.lower()
            file_size_mb = len(file_content) / (1024 * 1024)
            
            # Check file extension
            if file_ext not in DocumentValidator.SUPPORTED_TYPES:
                return False, f"Unsupported file type: {file_ext}. Supported: {list(DocumentValidator.SUPPORTED_TYPES.keys())}"
            
            # Check file size
            max_size = DocumentValidator.SUPPORTED_TYPES[file_ext]
            if file_size_mb > max_size:
                return False, f"File too large: {file_size_mb:.1f}MB. Max allowed: {max_size}MB"
            
            # Basic content validation
            if len(file_content) == 0:
                return False, "File is empty"

            if file_ext == ".docx":
                valid, reason = DOCXProcessor.validate_container(file_content)
                if not valid:
                    return False, f"Invalid or unsafe DOCX file: {reason}"
            
            # Check for potential security issues (basic)
            if DocumentValidator._has_suspicious_content(file_content, file_ext):
                return False, "File contains suspicious content"
            
            return True, "File validation passed"
            
        except Exception as e:
            return False, f"Validation failed ({type(e).__name__})"
    
    @staticmethod
    def _has_suspicious_content(file_content: bytes, file_ext: str = "") -> bool:
        """Basic check for suspicious content"""
        try:
            # Check for executable signatures
            suspicious_headers = [
                b'MZ',  # PE executable
                b'\x7fELF',  # ELF executable
                b'\xfe\xed\xfa',  # Mach-O
            ]
            
            for header in suspicious_headers:
                if file_content.startswith(header):
                    return True

            if file_content.startswith(b'PK\x03\x04'):
                return file_ext != ".docx"
            
            return False
        except Exception:
            return False


class DocumentProcessor:
    """Processes uploaded documents for RAG integration with duplicate detection"""
    
    def __init__(self, uploads_dir: str = None):
        self.uploads_dir = Path(uploads_dir or "uploads")
        self.uploads_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
        self.uploads_dir.chmod(0o750)
        self.supported_formats = set(DocumentValidator.SUPPORTED_TYPES)
        self.processed_hashes = set()  # Track processed file hashes in memory
        self.processing_hashes = set()
        self._hash_lock = threading.RLock()
        self._load_processed_hashes()
    
    def _load_processed_hashes(self):
        """Load hashes of previously processed files"""
        if not self.uploads_dir.exists():
            return
        
        for file_path in self.uploads_dir.glob("*_processed*.txt"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    # Read first few lines to find hash comment
                    for _ in range(10):
                        line = f.readline()
                        if line.startswith("# Content Hash:"):
                            hash_value = line.split(":")[1].strip()
                            with self._hash_lock:
                                self.processed_hashes.add(("unscoped", hash_value))
                            break
            except Exception:
                pass

    def check_duplicate(
        self, file_content: bytes, filename: str, corpus_id: str = "unscoped"
    ) -> Tuple[bool, str]:
        """Check if file content is a duplicate"""
        content_hash = hashlib.sha256(file_content).hexdigest()
        
        with self._hash_lock:
            cache_key = (str(corpus_id or "unscoped"), content_hash)
            is_processed = cache_key in self.processed_hashes
            is_processing = cache_key in self.processing_hashes

        if is_processed:
            return True, f"Duplicate detected: '{filename}' has already been processed (hash: {content_hash[:16]}...)"
        if is_processing:
            return True, f"Duplicate detected: '{filename}' is already being processed (hash: {content_hash[:16]}...)"
        
        return False, content_hash

    def _reserve_for_processing(
        self, file_content: bytes, filename: str, corpus_id: str = "unscoped"
    ) -> str:
        """Reserve a document hash so concurrent uploads do not process it twice."""
        content_hash = hashlib.sha256(file_content).hexdigest()
        cache_key = (str(corpus_id or "unscoped"), content_hash)
        with self._hash_lock:
            if cache_key in self.processed_hashes:
                raise ValueError(
                    f"Duplicate detected: '{filename}' has already been processed "
                    f"(hash: {content_hash[:16]}...)"
                )
            if cache_key in self.processing_hashes:
                raise ValueError(
                    f"Duplicate detected: '{filename}' is already being processed "
                    f"(hash: {content_hash[:16]}...)"
                )
            self.processing_hashes.add(cache_key)
        return content_hash
    
    def process_upload(
        self,
        file_content: bytes,
        filename: str,
        save_to_disk: bool = True,
        corpus_id: str = "unscoped",
        remember_processed: bool = True,
    ) -> Tuple[str, Dict[str, Any]]:
        """Process an uploaded file with duplicate detection.

        ``remember_processed=False`` keeps the hash reservation request-scoped:
        concurrent processing is still deduplicated, but a successful extraction
        does not enter the process-wide completed-hash set. This is intended for
        callers that activate a corpus separately and therefore must not make a
        failed downstream build look like a completed ingestion. Existing callers
        retain the historical process-wide behavior by default.
        """
        is_valid, validation_message = DocumentValidator.validate_file(filename, file_content)
        if not is_valid:
            raise ValueError(validation_message)

        file_path = Path(filename)
        file_ext = file_path.suffix.lower()
        
        if file_ext not in self.supported_formats:
            raise ValueError(f"Unsupported file format: {file_ext}")
        
        corpus_id = str(corpus_id or "unscoped")
        cache_key = (corpus_id, hashlib.sha256(file_content).hexdigest())
        content_hash = self._reserve_for_processing(file_content, filename, corpus_id=corpus_id)
        succeeded = False

        try:
            # Extract text based on file type
            if file_ext == '.pdf':
                # Plain text extraction captures CTI artefacts; table markdown is
                # added only on pages likely to contain CTI/IoC tables.
                text, pdf_metadata = PDFProcessor.extract_text_and_metadata(file_content)
                
                artifact_text = self._artifact_extraction_text(text, filename, pdf_metadata)
                artefacts = CTIArtifactExtractor.extract(artifact_text)
                document_quality = CTIArtifactExtractor.assess_extraction_quality(
                    text,
                    pages=pdf_metadata.get('pages', 0),
                    artefacts=artefacts,
                )
                metadata = {
                    'corpus_id': corpus_id,
                    'filename': filename,
                    'type': 'pdf',
                    'pages': pdf_metadata.get('pages', 0),
                    'characters': len(text),
                    'content_hash': content_hash,
                    'processed_at': datetime.now().isoformat(),
                    'processor_version': CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION,
                    'cti_artifacts': artefacts,
                    'artifact_counts': CTIArtifactExtractor.count_by_type(artefacts),
                    'document_quality': document_quality,
                }
                
                # Add PDF-specific metadata
                if pdf_metadata.get('title'):
                    metadata['pdf_title'] = pdf_metadata['title']
                if pdf_metadata.get('author'):
                    metadata['pdf_author'] = pdf_metadata['author']
                
            elif file_ext == '.docx':
                text, metadata = DOCXProcessor.extract_text_and_metadata(file_content, filename)
                metadata['content_hash'] = content_hash
                metadata['processor_version'] = CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION
                artefacts = CTIArtifactExtractor.extract(self._artifact_extraction_text(text, filename, metadata))
                metadata['cti_artifacts'] = artefacts
                metadata['artifact_counts'] = CTIArtifactExtractor.count_by_type(artefacts)
                metadata['document_quality'] = CTIArtifactExtractor.assess_extraction_quality(
                    text,
                    pages=1,
                    artefacts=artefacts,
                )
            elif file_ext in {'.txt', '.md', '.markdown'}:
                text, metadata = self._process_text(file_content, filename)
                metadata['content_hash'] = content_hash
                metadata['processor_version'] = CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION
                artefacts = CTIArtifactExtractor.extract(self._artifact_extraction_text(text, filename, metadata))
                metadata['cti_artifacts'] = artefacts
                metadata['artifact_counts'] = CTIArtifactExtractor.count_by_type(artefacts)
                metadata['document_quality'] = CTIArtifactExtractor.assess_extraction_quality(
                    text,
                    pages=1,
                    artefacts=artefacts,
                )
            elif file_ext in {'.html', '.htm'}:
                text, metadata = HTMLProcessor.extract_text_and_metadata(file_content, filename)
                metadata['content_hash'] = content_hash
                metadata['processor_version'] = CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION
                artefacts = CTIArtifactExtractor.extract(self._artifact_extraction_text(text, filename, metadata))
                metadata['cti_artifacts'] = artefacts
                metadata['artifact_counts'] = CTIArtifactExtractor.count_by_type(artefacts)
                metadata['document_quality'] = CTIArtifactExtractor.assess_extraction_quality(
                    text,
                    pages=1,
                    artefacts=artefacts,
                )
            elif file_ext in {'.csv', '.tsv'}:
                text, metadata = CSVProcessor.extract_text_and_metadata(file_content, filename)
                metadata['content_hash'] = content_hash
                metadata['processor_version'] = CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION
                artefacts = CTIArtifactExtractor.extract(self._artifact_extraction_text(text, filename, metadata))
                metadata['cti_artifacts'] = artefacts
                metadata['artifact_counts'] = CTIArtifactExtractor.count_by_type(artefacts)
                metadata['document_quality'] = CTIArtifactExtractor.assess_extraction_quality(
                    text,
                    pages=1,
                    artefacts=artefacts,
                )
            elif file_ext in {'.json', '.stix'}:
                text, metadata = JSONProcessor.extract_text_and_metadata(file_content, filename)
                metadata['content_hash'] = content_hash
                metadata['processor_version'] = CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION
                text_artifacts = CTIArtifactExtractor.extract(self._artifact_extraction_text(text, filename, metadata))
                artefacts = CTIArtifactExtractor.merge_artifacts(
                    text_artifacts,
                    metadata.get("structured_cti_artifacts") if isinstance(metadata, dict) else {},
                )
                metadata['cti_artifacts'] = artefacts
                metadata['artifact_counts'] = CTIArtifactExtractor.count_by_type(artefacts)
                metadata['document_quality'] = CTIArtifactExtractor.assess_extraction_quality(
                    text,
                    pages=1,
                    artefacts=artefacts,
                )
            elif file_ext in {'.yaml', '.yml'}:
                text, metadata = YAMLProcessor.extract_text_and_metadata(file_content, filename)
                metadata['content_hash'] = content_hash
                metadata['processor_version'] = CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION
                text_artifacts = CTIArtifactExtractor.extract(self._artifact_extraction_text(text, filename, metadata))
                artefacts = CTIArtifactExtractor.merge_artifacts(
                    text_artifacts,
                    metadata.get("structured_cti_artifacts") if isinstance(metadata, dict) else {},
                )
                metadata['cti_artifacts'] = artefacts
                metadata['artifact_counts'] = CTIArtifactExtractor.count_by_type(artefacts)
                metadata['document_quality'] = CTIArtifactExtractor.assess_extraction_quality(
                    text,
                    pages=1,
                    artefacts=artefacts,
                )
            elif file_ext == '.xml':
                text, metadata = XMLProcessor.extract_text_and_metadata(file_content, filename)
                metadata['content_hash'] = content_hash
                metadata['processor_version'] = CTIArtifactExtractor.EXTRACTION_PIPELINE_VERSION
                artefacts = CTIArtifactExtractor.extract(self._artifact_extraction_text(text, filename, metadata))
                metadata['cti_artifacts'] = artefacts
                metadata['artifact_counts'] = CTIArtifactExtractor.count_by_type(artefacts)
                metadata['document_quality'] = CTIArtifactExtractor.assess_extraction_quality(
                    text,
                    pages=1,
                    artefacts=artefacts,
                )
            else:
                raise ValueError(f"Unsupported file format: {file_ext}")

            metadata['corpus_id'] = corpus_id
            
            # Optionally save to disk
            if save_to_disk:
                saved_path = self._save_to_disk(text, filename, metadata)
                metadata['saved_path'] = saved_path.name
                print("Saved processed upload")
            else:
                print("Processed upload in memory only")
            
            print(f"Successfully processed upload ({len(text)} extracted characters)")
            succeeded = True
            return text, metadata
        finally:
            with self._hash_lock:
                self.processing_hashes.discard(cache_key)
                if succeeded and remember_processed:
                    self.processed_hashes.add(cache_key)
    
    def _process_text(self, file_content: bytes, filename: str) -> Tuple[str, Dict[str, Any]]:
        """Process text/markdown content"""
        try:
            encodings = ['utf-8', 'latin-1', 'cp1252']
            text = None
            
            for encoding in encodings:
                try:
                    text = file_content.decode(encoding)
                    break
                except UnicodeDecodeError:
                    continue
            
            if text is None:
                raise ValueError(f"Unable to decode text file {filename}")
            
            metadata = {
                'filename': filename,
                'type': 'text',
                'characters': len(text),
                'processed_at': datetime.now().isoformat()
            }
            
            return text, metadata
            
        except Exception as e:
            raise ValueError(f"Failed to process text file {Path(filename).name} ({type(e).__name__})") from e

    @staticmethod
    def _artifact_extraction_text(text: str, filename: str = "", metadata: Dict[str, Any] = None) -> str:
        """Extract from body-derived content without filename/PDF metadata leakage."""
        metadata = metadata or {}
        aliases = metadata.get("aliases")
        if isinstance(aliases, (list, tuple, set)):
            alias_text = "aliases: " + ", ".join(str(alias) for alias in aliases if alias)
        elif aliases:
            alias_text = f"aliases: {aliases}"
        else:
            alias_text = ""
        identity_values = [
            metadata.get("json_title"),
            metadata.get("html_title"),
            alias_text,
        ]
        identity_text = "\n".join(str(value) for value in identity_values if value)
        return f"{identity_text}\n{text or ''}" if identity_text else str(text or "")
    
    def _save_to_disk(self, text: str, filename: str, metadata: Dict[str, Any]) -> Path:
        """Save processed text to disk with hash for duplicate detection"""
        safe_filename = self._sanitize_filename(filename)
        base_name = Path(safe_filename).stem
        save_path = self.uploads_dir / f"{base_name}_processed.txt"
        
        counter = 1
        while save_path.exists():
            save_path = self.uploads_dir / f"{base_name}_processed_{counter}.txt"
            counter += 1
        
        try:
            header = [
                f"# Processed Document: {safe_filename}",
                f"# Content Hash: {metadata.get('content_hash', 'unknown')}",
                f"# Processed at: {metadata['processed_at']}",
                f"# Processor Version: {metadata.get('processor_version', 'unknown')}",
                f"# Type: {metadata['type']}",
            ]
            if 'pages' in metadata:
                header.append(f"# Pages: {metadata['pages']}")
            if metadata.get('artifact_counts'):
                header.append(
                    "# CTI Artifact Counts: "
                    + json.dumps(metadata['artifact_counts'], sort_keys=True)
                )
            header.append(f"# Characters: {metadata['characters']}")
            atomic_write_text(
                save_path,
                "\n".join(header) + "\n\n" + "=" * 50 + "\n\n" + text,
            )
            return save_path
            
        except Exception as e:
            log_sanitized_exception("Uploaded document save failed", e)
            raise
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe disk storage"""
        basename = str(filename or "uploaded_document").replace("\\", "/").rsplit("/", 1)[-1]
        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", basename).strip(" ._")
        return (safe_name or "uploaded_document")[:200]
