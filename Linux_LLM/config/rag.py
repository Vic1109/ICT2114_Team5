import io
from pathlib import Path
from typing import List, Dict, Tuple, Any, Optional
from datetime import datetime
try:
    import pymupdf  # PyMuPDF >= 1.24
except ImportError:  # pragma: no cover - depends on deployment package version
    import fitz as pymupdf  # PyMuPDF legacy import name
import hashlib
import json
import re
import threading
from urllib.parse import urlparse
from cti_artifacts import CTIArtifactExtractor
from runtime_utils import configure_console_encoding


configure_console_encoding()


class PDFProcessor:
    """Handles PDF document text extraction"""
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
            doc = pymupdf.open(stream=pdf_stream, filetype="pdf")
            
            full_text = []
            metadata = {
                'pages': len(doc),
                'title': doc.metadata.get('title', ''),
                'author': doc.metadata.get('author', ''),
                'subject': doc.metadata.get('subject', ''),
                'creator': doc.metadata.get('creator', ''),
                'producer': doc.metadata.get('producer', ''),
                'creation_date': doc.metadata.get('creationDate', ''),
                'modification_date': doc.metadata.get('modDate', '')
            }
            
            for page_num in range(len(doc)):
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
                        print(f"WARNING: Table extraction skipped on page {page_num + 1}: {table_error}")

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
                
                full_text.append("\n".join(page_parts))
            
            doc.close()
            primary_text = "\n".join(full_text)
            fallback_text = PDFProcessor._extract_pypdf_text(file_content)
            merged_text, fallback_metadata = PDFProcessor._merge_fallback_text_if_useful(
                primary_text,
                fallback_text,
                pages=metadata.get("pages", 0),
            )
            metadata.update(fallback_metadata)
            return merged_text, metadata
            
        except Exception as e:
            print(f"WARNING: pymupdf extraction error: {e}")
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
            parts = []
            for page_num, page in enumerate(reader.pages):
                try:
                    page_text = page.extract_text() or ""
                except Exception:
                    page_text = ""
                page_text = page_text.strip()
                if page_text:
                    parts.append(f"\n--- PYPDF Fallback Page {page_num + 1} ---\n{page_text}")
            return "\n".join(parts)
        except Exception as error:
            print(f"WARNING: pypdf fallback extraction skipped: {error}")
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
    
    @staticmethod
    def get_metadata(file_content: bytes) -> Dict[str, Any]:
        """Extract PDF metadata"""
        try:
            pdf_stream = io.BytesIO(file_content)
            doc = pymupdf.open(stream=pdf_stream, filetype="pdf")
            
            metadata = {
                'pages': len(doc),
                'title': doc.metadata.get('title', ''),
                'author': doc.metadata.get('author', ''),
                'subject': doc.metadata.get('subject', ''),
                'creator': doc.metadata.get('creator', ''),
                'producer': doc.metadata.get('producer', ''),
                'creation_date': doc.metadata.get('creationDate', ''),
                'modification_date': doc.metadata.get('modDate', '')
            }
            
            doc.close()
            return metadata
            
        except Exception as e:
            print(f"WARNING: Metadata extraction error: {e}")
            return {'pages': 0}
    
    @staticmethod
    def extract_with_structure(file_content: bytes) -> Dict[str, Any]:
        """Extract with document structure preserved"""
        try:
            pdf_stream = io.BytesIO(file_content)
            doc = pymupdf.open(stream=pdf_stream, filetype="pdf")
            
            structured = {
                "title": doc.metadata.get("title", ""),
                "author": doc.metadata.get("author", ""),
                "pages": [],
                "toc": doc.get_toc(),  # Table of contents
                "images": []
            }
            
            for page_num in range(len(doc)):
                page = doc[page_num]
                
                page_data = {
                    "number": page_num + 1,
                    "text": page.get_text(),
                    "links": [link["uri"] for link in page.get_links() if "uri" in link],
                    "images": len(page.get_images())
                }
                
                structured["pages"].append(page_data)
            
            doc.close()
            return structured
            
        except Exception as e:
            print(f"WARNING: Structure extraction error: {e}")
            return {}


class TextProcessor:
    """Handles plain text file processing"""
    
    @staticmethod
    def extract_text(file_content: bytes, encoding: str = 'utf-8') -> str:
        """Extract text from plain text files"""
        try:
            return file_content.decode(encoding, errors='ignore').strip()
        except Exception as e:
            print(f"WARNING: Text extraction error: {e}")
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
            print(f"WARNING: Markdown extraction error: {e}")
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
            f"Source file: {filename}" if filename else "",
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


class DocumentValidator:
    """Validates documents for security and content quality"""
    
    # Supported file types and their max sizes (in MB)
    SUPPORTED_TYPES = {
        '.pdf': 10,
        '.txt': 5,
        '.md': 5,
        '.markdown': 5,
        '.json': 5
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
            
            # Check for potential security issues (basic)
            if DocumentValidator._has_suspicious_content(file_content):
                return False, "File contains suspicious content"
            
            return True, "File validation passed"
            
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    @staticmethod
    def _has_suspicious_content(file_content: bytes) -> bool:
        """Basic check for suspicious content"""
        try:
            # Check for executable signatures
            suspicious_headers = [
                b'MZ',  # PE executable
                b'\x7fELF',  # ELF executable
                b'\xfe\xed\xfa',  # Mach-O
                b'PK\x03\x04',  # ZIP (could be JAR/etc)
            ]
            
            for header in suspicious_headers:
                if file_content.startswith(header):
                    return True
            
            return False
        except Exception:
            return False


class DocumentProcessor:
    """Processes uploaded documents for RAG integration with duplicate detection"""
    
    def __init__(self, uploads_dir: str = None):
        self.uploads_dir = Path(uploads_dir or "uploads")
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        self.supported_formats = {'.pdf', '.txt', '.md', '.markdown', '.json'}
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
                                self.processed_hashes.add(hash_value)
                            break
            except Exception:
                pass

    def reset_duplicate_tracking(self) -> Dict[str, int]:
        """Clear in-memory upload dedupe state after the RAG store is reset.

        Processed text files on disk are intentionally left untouched. The web
        upload path processes CTI documents in memory, so a database rebuild
        needs only the session-level hash cache cleared to allow the same source
        documents to be ingested again with the current extraction pipeline.
        """
        with self._hash_lock:
            processed_count = len(self.processed_hashes)
            processing_count = len(self.processing_hashes)
            self.processed_hashes.clear()
            self.processing_hashes.clear()

        return {
            "processed_hashes_cleared": processed_count,
            "processing_hashes_cleared": processing_count,
        }
    
    def check_duplicate(self, file_content: bytes, filename: str) -> Tuple[bool, str]:
        """Check if file content is a duplicate"""
        content_hash = hashlib.sha256(file_content).hexdigest()
        
        with self._hash_lock:
            is_processed = content_hash in self.processed_hashes
            is_processing = content_hash in self.processing_hashes

        if is_processed:
            return True, f"Duplicate detected: '{filename}' has already been processed (hash: {content_hash[:16]}...)"
        if is_processing:
            return True, f"Duplicate detected: '{filename}' is already being processed (hash: {content_hash[:16]}...)"
        
        return False, content_hash

    def _reserve_for_processing(self, file_content: bytes, filename: str) -> str:
        """Reserve a document hash so concurrent uploads do not process it twice."""
        content_hash = hashlib.sha256(file_content).hexdigest()
        with self._hash_lock:
            if content_hash in self.processed_hashes:
                raise ValueError(
                    f"Duplicate detected: '{filename}' has already been processed "
                    f"(hash: {content_hash[:16]}...)"
                )
            if content_hash in self.processing_hashes:
                raise ValueError(
                    f"Duplicate detected: '{filename}' is already being processed "
                    f"(hash: {content_hash[:16]}...)"
                )
            self.processing_hashes.add(content_hash)
        return content_hash
    
    def process_upload(self, file_content: bytes, filename: str, save_to_disk: bool = True) -> Tuple[str, Dict[str, Any]]:
        """Process uploaded file with duplicate detection"""
        is_valid, validation_message = DocumentValidator.validate_file(filename, file_content)
        if not is_valid:
            raise ValueError(validation_message)

        file_path = Path(filename)
        file_ext = file_path.suffix.lower()
        
        if file_ext not in self.supported_formats:
            raise ValueError(f"Unsupported file format: {file_ext}")
        
        content_hash = self._reserve_for_processing(file_content, filename)
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
            elif file_ext == '.json':
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
            else:
                raise ValueError(f"Unsupported file format: {file_ext}")
            
            # Optionally save to disk
            if save_to_disk:
                saved_path = self._save_to_disk(text, filename, metadata)
                metadata['saved_path'] = str(saved_path)
                print(f"Saved processed file: {saved_path.name}")
            else:
                print(f"Processed in memory only: {filename}")
            
            print(f"Successfully processed: {filename} ({len(text)} chars, hash: {content_hash[:16]}...)")
            succeeded = True
            return text, metadata
        finally:
            with self._hash_lock:
                self.processing_hashes.discard(content_hash)
                if succeeded:
                    self.processed_hashes.add(content_hash)
    
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
            raise ValueError(f"Failed to process text file {filename}: {str(e)}")

    @staticmethod
    def _artifact_extraction_text(text: str, filename: str = "", metadata: Dict[str, Any] = None) -> str:
        """Include document identity fields when extracting CTI metadata."""
        metadata = metadata or {}
        aliases = metadata.get("aliases")
        if isinstance(aliases, (list, tuple, set)):
            alias_text = "aliases: " + ", ".join(str(alias) for alias in aliases if alias)
        elif aliases:
            alias_text = f"aliases: {aliases}"
        else:
            alias_text = ""
        identity_values = [
            filename,
            metadata.get("title"),
            metadata.get("pdf_title"),
            metadata.get("json_title"),
            metadata.get("subject"),
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
            with open(save_path, 'w', encoding='utf-8') as f:
                # Write metadata header with hash for duplicate detection
                f.write(f"# Processed Document: {filename}\n")
                f.write(f"# Content Hash: {metadata.get('content_hash', 'unknown')}\n")
                f.write(f"# Processed at: {metadata['processed_at']}\n")
                f.write(f"# Processor Version: {metadata.get('processor_version', 'unknown')}\n")
                f.write(f"# Type: {metadata['type']}\n")
                if 'pages' in metadata:
                    f.write(f"# Pages: {metadata['pages']}\n")
                if 'pdf_title' in metadata:
                    f.write(f"# PDF Title: {metadata['pdf_title']}\n")
                if 'pdf_author' in metadata:
                    f.write(f"# PDF Author: {metadata['pdf_author']}\n")
                if metadata.get('artifact_counts'):
                    f.write(f"# CTI Artifact Counts: {metadata['artifact_counts']}\n")
                f.write(f"# Characters: {metadata['characters']}\n")
                f.write("\n" + "="*50 + "\n\n")
                f.write(text)
            
            return save_path
            
        except Exception as e:
            print(f"WARNING: Failed to save {filename}: {e}")
            raise
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe disk storage"""
        unsafe_chars = '<>:"/\\|*'
        safe_name = filename
        for char in unsafe_chars:
            safe_name = safe_name.replace(char, '_')
        return safe_name
