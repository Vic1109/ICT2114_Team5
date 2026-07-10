import asyncio
import os
from pathlib import Path
from typing import Optional, Dict, Any
import logging
import re
from urllib.parse import unquote, urlparse
from urllib.request import url2pathname
from uuid import uuid4

from runtime_utils import log_sanitized_exception


MAX_MARKDOWN_BYTES = 5 * 1024 * 1024
MAX_LOCAL_RESOURCE_BYTES = 20 * 1024 * 1024
MAX_BATCH_REPORTS = 100
ALLOWED_RESOURCE_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".svg"}

WEASYPRINT_IMPORT_ERROR = None
MARKDOWN_IMPORT_ERROR = None

try:
    import weasyprint
except Exception as exc:
    weasyprint = None
    WEASYPRINT_IMPORT_ERROR = type(exc).__name__

try:
    import markdown
except Exception as exc:
    markdown = None
    MARKDOWN_IMPORT_ERROR = type(exc).__name__


class EnhancedPDFConverter:
    def __init__(self):
        self.logger = logging.getLogger("EnhancedPDFConverter")
        self.logger.setLevel(logging.INFO)
        
        # Check available conversion methods
        self.conversion_method = self._detect_conversion_method()
        self.conversion_available = self.conversion_method != "none"
        
        self.logger.info(f"🔧 PDF conversion method: {self.conversion_method}")
    
    def _detect_conversion_method(self) -> str:
        if weasyprint is not None and markdown is not None:
            self.logger.info("✅ WeasyPrint available")
            return "weasyprint"

        if WEASYPRINT_IMPORT_ERROR:
            self.logger.warning("WeasyPrint is unavailable")
        if MARKDOWN_IMPORT_ERROR:
            self.logger.warning("Markdown renderer is unavailable")
        self.logger.warning(" No PDF conversion method available")
        return "none"
    
    async def convert_markdown_to_pdf(self, markdown_path: Path, 
                                    output_dir: Optional[Path] = None,
                                    custom_css: Optional[str] = None) -> Optional[Path]:
        try:
            markdown_path = Path(markdown_path).resolve()

            # Validate input
            if not markdown_path.is_file():
                self.logger.error("Markdown input was not found")
                return None
            if markdown_path.stat().st_size > MAX_MARKDOWN_BYTES:
                self.logger.error("Markdown input exceeds the PDF conversion limit")
                return None
            
            if not self.conversion_available:
                self.logger.error("❌ No PDF conversion method available")
                return None
            
            if output_dir is None:
                output_dir = markdown_path.parent

            reports_root = Path(output_dir).resolve()
            try:
                markdown_path.relative_to(reports_root)
            except ValueError:
                self.logger.error(
                    "Refusing to convert a Markdown file outside the reports directory",
                )
                return None

            output_path = (reports_root / f"{markdown_path.stem}.pdf").resolve()
            try:
                output_path.relative_to(reports_root)
            except ValueError:
                self.logger.error(
                    "Refusing to write a PDF outside the reports directory",
                )
                return None
            
            success = False
            
            if self.conversion_method == "weasyprint":
                success = await self._convert_with_weasyprint(
                    markdown_path,
                    output_path,
                    reports_root,
                    custom_css,
                )
            
            if success and output_path.exists():
                self.logger.info(f"✅ PDF created: {output_path.name}")
                return output_path
            else:
                self.logger.error(f"❌ PDF conversion failed for {markdown_path.name}")
                return None
                
        except Exception as error:
            log_sanitized_exception("Unexpected PDF conversion failure", error, logger=self.logger)
            return None
    
    async def _convert_with_weasyprint(
        self,
        md_path: Path,
        pdf_path: Path,
        reports_root: Path,
        custom_css: Optional[str] = None,
    ) -> bool:
        """Render in a worker so synchronous WeasyPrint work cannot block FastAPI."""
        return await asyncio.to_thread(
            self._convert_with_weasyprint_sync,
            md_path,
            pdf_path,
            reports_root,
            custom_css,
        )

    @staticmethod
    def _resolve_local_resource(resource_url: str, reports_root: Path) -> Path:
        """Resolve a WeasyPrint resource URL inside the configured reports root."""
        parsed = urlparse(str(resource_url or ""))
        scheme = parsed.scheme.lower()
        if scheme not in ("", "file"):
            raise ValueError("PDF resource URL scheme is not allowed")
        if parsed.netloc:
            raise ValueError("PDF resource URL host is not allowed")

        if scheme == "file":
            resource_path = Path(url2pathname(unquote(parsed.path)))
        else:
            resource_path = reports_root / unquote(parsed.path)

        reports_root = reports_root.resolve()
        resolved_path = resource_path.resolve()
        try:
            resolved_path.relative_to(reports_root)
        except ValueError as error:
            raise ValueError("PDF resource is outside the reports directory") from error
        if not resolved_path.is_file():
            raise ValueError("PDF resource is not a readable local file")
        if resolved_path.suffix.lower() not in ALLOWED_RESOURCE_SUFFIXES:
            raise ValueError("PDF resource type is not allowed")
        if resolved_path.stat().st_size > MAX_LOCAL_RESOURCE_BYTES:
            raise ValueError("PDF resource exceeds the configured size limit")
        return resolved_path

    @classmethod
    def _local_only_url_fetcher(cls, reports_root: Path):
        """Build a WeasyPrint fetcher that cannot reach network or arbitrary files."""
        allowed_root = reports_root.resolve()

        def fetch(resource_url: str) -> Dict[str, Any]:
            if weasyprint is None:  # pragma: no cover - guarded before rendering
                raise RuntimeError("WeasyPrint is unavailable")
            local_path = cls._resolve_local_resource(resource_url, allowed_root)
            return weasyprint.default_url_fetcher(local_path.as_uri())

        return fetch

    def _convert_with_weasyprint_sync(
        self,
        md_path: Path,
        pdf_path: Path,
        reports_root: Path,
        custom_css: Optional[str] = None,
    ) -> bool:
        try:
            if weasyprint is None or markdown is None:
                missing = []
                if weasyprint is None:
                    missing.append(f"WeasyPrint ({WEASYPRINT_IMPORT_ERROR or 'not installed'})")
                if markdown is None:
                    missing.append(f"markdown ({MARKDOWN_IMPORT_ERROR or 'not installed'})")
                raise ImportError(", ".join(missing))
            
            with open(md_path, 'r', encoding='utf-8') as f:
                md_content = f.read()
            if '|' in md_content:
                self.logger.info("📋 Markdown contains pipe characters (potential tables)")
            
            html_content = markdown.markdown(
                md_content,
                extensions=['tables', 'fenced_code', 'toc']
            )
            
            # Improve table rendering when markdown conversion leaves pipe tables unparsed.
            if '<table>' in html_content:
                self.logger.info("✅ Tables successfully converted to HTML")
            else:
                self.logger.warning("⚠️ No HTML tables found - markdown tables may not be properly formatted")
                # Log a snippet of the markdown around tables
                table_sections = re.findall(r'(\|[^\n]+\|[\n\r]+){2,}', md_content)
                if table_sections:
                    self.logger.debug(f"Found {len(table_sections)} potential table sections")
            css = custom_css or self._get_default_css()
            full_html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>SOC Threat Analysis Report</title>
    <style>
    {css}
    </style>
</head>
<body>
    {html_content}
</body>
</html>
"""
            
            temporary = pdf_path.with_name(f".{pdf_path.stem}.{uuid4().hex}.tmp.pdf")
            try:
                html_doc = weasyprint.HTML(
                    string=full_html,
                    base_url=md_path.parent.as_uri().rstrip("/") + "/",
                    url_fetcher=self._local_only_url_fetcher(reports_root),
                )
                html_doc.write_pdf(str(temporary))
                os.chmod(temporary, 0o640)
                os.replace(temporary, pdf_path)
                return True
            except Exception as e:
                log_sanitized_exception("WeasyPrint conversion failed", e, logger=self.logger)
                return False
            finally:
                temporary.unlink(missing_ok=True)
            
        except ImportError:
            self.logger.error("WeasyPrint conversion dependencies are unavailable")
            return False
        except Exception as e:
            log_sanitized_exception("WeasyPrint conversion failed", e, logger=self.logger)
            return False
    
    def _get_default_css(self) -> str:
        return """
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #000000;
            margin: 40px;
            background-color: #ffffff;
            max-width: 1200px;
            word-wrap: break-word;           /* Force word wrapping */
            overflow-wrap: break-word;       /* Modern word wrapping */
            hyphens: auto;                   /* Enable hyphenation */
            -webkit-hyphens: auto;
            -moz-hyphens: auto;
            -ms-hyphens: auto;
        }
        img {
            max-width: 100%;
            height: auto;
            display: block;
            margin: 20px auto;
            border: 1px solid #ddd;
            border-radius: 5px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }

        .chart-container {
            text-align: center;
            margin: 30px 0;
            page-break-inside: avoid;
        }
        /* Enhanced text wrapping for all text elements */
        h1, h2, h3, h4, h5, h6, p, li, td, th {
            word-wrap: break-word;
            overflow-wrap: break-word;
            word-break: break-word;          /* Break long words if needed */
            hyphens: auto;
        }
        
        h1 {
            color: #000000;
            border-bottom: 3px solid #000000;
            padding-bottom: 10px;
            font-size: 28px;
            page-break-after: avoid;
            line-height: 1.2;               /* Tighter line height for headers */
        }
        
        h2, h3 {
            color: #000000;
            margin-top: 30px;
            margin-bottom: 15px;
            font-size: 22px;
            page-break-after: avoid;
            line-height: 1.3;
        }
        
        h3 {
            font-size: 18px;
            margin-top: 25px;
            margin-bottom: 12px;
            line-height: 1.4;
        }
        
        /* Paragraph styling with better spacing */
        p {
            margin: 12px 0;
            text-align: justify;             /* Justified text for better appearance */
            text-justify: inter-word;
            line-height: 1.6;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 1em 0;
        }

        th,
        td {
            border: 1px solid #ddd;
            padding: 8px;
        }

        th {
            background-color: #f4f4f4;
        }
        
        /* Code blocks with horizontal scrolling prevention */
        code {
            background-color: #f0f0f0;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 90%;
            border: 1px solid #dddddd;
            word-wrap: break-word;           /* Wrap code text */
            overflow-wrap: break-word;
            white-space: pre-wrap;           /* Preserve formatting but allow wrapping */
            word-break: break-all;           /* Break long code lines */
        }
        
        pre {
            background-color: #f0f0f0;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #000000;
            page-break-inside: avoid;
            white-space: pre-wrap;           /* Preserve formatting but allow wrapping */
            word-wrap: break-word;
            overflow-wrap: break-word;
            word-break: break-all;
            max-width: 100%;                 /* Prevent overflow */
            overflow-x: hidden;              /* Hide horizontal scroll */
        }
        
        pre code {
            background: none;
            border: none;
            padding: 0;
            font-size: 13px;
            line-height: 1.4;
            white-space: pre-wrap;
            word-break: break-all;
        }
        
        /* Enhanced blockquotes */
        blockquote {
            border-left: 4px solid #000000;
            margin: 20px 0;
            padding-left: 20px;
            color: #000000;
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 0 5px 5px 0;
            word-wrap: break-word;
            overflow-wrap: break-word;
            font-style: italic;
        }
        
        /* List styling with better spacing */
        ul, ol {
            margin: 15px 0;
            padding-left: 30px;
        }
        
        li {
            margin: 8px 0;
            word-wrap: break-word;
            overflow-wrap: break-word;
            line-height: 1.5;
        }
        
        /* Long URL handling */
        a {
            word-wrap: break-word;
            overflow-wrap: break-word;
            word-break: break-all;           /* Break long URLs */
            color: #000000;
            text-decoration: underline;
        }
        
        /* Alert boxes with proper text wrapping */
        .alert-critical, .alert-high, .alert-medium {
            background-color: #ffffff;
            color: #000000;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            border: 2px solid #000000;
            word-wrap: break-word;
            overflow-wrap: break-word;
            line-height: 1.5;
        }
        
        .metadata {
            background-color: #f5f5f5;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #000000;
            margin: 20px 0;
            font-size: 14px;
            word-wrap: break-word;
            overflow-wrap: break-word;
            line-height: 1.4;
        }
        
        /* Enhanced print media queries */
        @media print {
            body { 
                margin: 20px; 
                font-size: 12pt;
                line-height: 1.4;
            }
            
            h1 { 
                page-break-before: auto;
                font-size: 20pt;
            }
            
            h2 { font-size: 16pt; }
            h3 { font-size: 14pt; }
            
            table { 
                page-break-inside: avoid;
                font-size: 10pt;
            }
            
            tr { page-break-inside: avoid; }
            
            .page-break { page-break-before: always; }
            
            /* Ensure code blocks don't cause overflow */
            pre, code {
                font-size: 9pt;
                line-height: 1.2;
            }
        }
        
        /* Page settings with proper margins */
        @page {
            margin: 1in;
            size: A4;
            @bottom-right {
                content: "Page " counter(page) " of " counter(pages);
                font-size: 10pt;
            }
        }
        
        /* Special handling for very long strings without spaces */
        .force-wrap {
            word-break: break-all;
            overflow-wrap: break-word;
            hyphens: none;
        }
        """
    
    async def batch_convert_reports(self, reports_dir: Path,
                                  pattern: str = "*.md") -> Dict[str, Any]:
        """Enhanced batch convert multiple markdown reports"""
        results = {
            "converted": [],
            "failed": [],
            "skipped": [],
            "total_processed": 0,
            "conversion_method": self.conversion_method,
            "errors": []
        }
        
        try:
            if not self.conversion_available:
                results["errors"].append("No PDF conversion method available")
                return results
            
            reports_dir = Path(reports_dir).resolve()
            markdown_files = sorted(reports_dir.glob(pattern))
            results["total_processed"] = len(markdown_files)

            if len(markdown_files) > MAX_BATCH_REPORTS:
                results["errors"].append(
                    f"Batch contains more than {MAX_BATCH_REPORTS} markdown reports"
                )
                return results
            
            if not markdown_files:
                results["errors"].append("No markdown files found")
                return results
            
            for md_file in markdown_files:
                try:
                    # Skip if PDF already exists and is newer
                    pdf_file = md_file.with_suffix('.pdf')
                    if (
                        pdf_file.exists()
                        and pdf_file.stat().st_mtime > md_file.stat().st_mtime
                    ):
                        results["skipped"].append(md_file.name)
                        continue

                    # Each render yields to the event loop and executes in a worker.
                    pdf_path = await self.convert_markdown_to_pdf(md_file, reports_dir)

                    if pdf_path:
                        results["converted"].append(pdf_path.name)
                    else:
                        results["failed"].append(md_file.name)

                except Exception as error:
                    log_sanitized_exception("PDF batch item failed", error, logger=self.logger)
                    results["failed"].append(md_file.name)
                    results["errors"].append(
                        f"{md_file.name}: PDF conversion failed"
                    )
            
            self.logger.info(f" Batch conversion complete: {len(results['converted'])} converted, "
                           f"{len(results['failed'])} failed, {len(results['skipped'])} skipped")
            
        except Exception as error:
            log_sanitized_exception("Batch PDF conversion failed", error, logger=self.logger)
            results["errors"].append("Batch PDF conversion failed")
        
        return results
    
    def get_conversion_status(self) -> Dict[str, Any]:
        status = {
            "method": self.conversion_method,
            "available": self.conversion_available,
            "capabilities": self._check_capabilities(),
            "recommendations": []
        }
        
        if not self.conversion_available:
            status["recommendations"].extend([
                "Install Python packages: pip install weasyprint markdown",
                "Install WeasyPrint native dependencies such as Pango, Cairo, GDK-PixBuf, and GLib"
            ])
            if WEASYPRINT_IMPORT_ERROR:
                status["weasyprint_error"] = "unavailable"
            if MARKDOWN_IMPORT_ERROR:
                status["markdown_error"] = "unavailable"
        
        return status
    
    def _check_capabilities(self) -> Dict[str, Any]:
        capabilities = {}
        
        capabilities["weasyprint"] = weasyprint is not None
        capabilities["markdown"] = markdown is not None
        capabilities["weasyprint_error"] = "unavailable" if WEASYPRINT_IMPORT_ERROR else None
        capabilities["markdown_error"] = "unavailable" if MARKDOWN_IMPORT_ERROR else None
        
        return capabilities


class EnhancedPDFAPIHandlers:
    
    def __init__(self, pdf_converter: EnhancedPDFConverter, reports_dir: Path):
        self.pdf_converter = pdf_converter
        self.reports_dir = reports_dir
        self.logger = logging.getLogger("EnhancedPDFAPI")
    
    async def handle_single_conversion(self, filename: str) -> Dict[str, Any]:
        try:
            if (
                not filename
                or not filename.endswith('.md')
                or "/" in filename
                or "\\" in filename
            ):
                return {
                    "success": False,
                    "error": "Invalid filename - must be a .md file"
                }
            
            reports_root = self.reports_dir.resolve()
            md_path = (reports_root / filename).resolve()
            if md_path.parent != reports_root:
                return {
                    "success": False,
                    "error": "Invalid filename - must be inside reports directory"
                }
            
            if not md_path.is_file():
                return {
                    "success": False,
                    "error": f"Markdown report not found: {filename}"
                }
            
            if not self.pdf_converter.conversion_available:
                return {
                    "success": False,
                    "error": "PDF conversion not available - check system dependencies",
                    "recommendations": self.pdf_converter.get_conversion_status()["recommendations"]
                }
            
            pdf_path = await self.pdf_converter.convert_markdown_to_pdf(
                md_path, self.reports_dir
            )
            
            if pdf_path:
                return {
                    "success": True,
                    "pdf_filename": pdf_path.name,
                    "message": f"PDF conversion successful: {pdf_path.name}",
                    "method": self.pdf_converter.conversion_method
                }
            else:
                return {
                    "success": False,
                    "error": "PDF conversion failed - check logs for details",
                    "method": self.pdf_converter.conversion_method
                }
                
        except Exception as error:
            log_sanitized_exception("Single PDF conversion failed", error, logger=self.logger)
            return {
                "success": False,
                "error": "PDF conversion failed - check server logs"
            }
    
    async def handle_batch_conversion(self) -> Dict[str, Any]:
        """Handle batch conversion with enhanced error handling"""
        try:
            if not self.pdf_converter.conversion_available:
                return {
                    "success": False,
                    "error": "PDF conversion not available - check system dependencies",
                    "recommendations": self.pdf_converter.get_conversion_status()["recommendations"]
                }
            
            results = await self.pdf_converter.batch_convert_reports(self.reports_dir)
            
            return {
                "success": True,
                "results": results,
                "summary": f"Converted {len(results['converted'])}, failed {len(results['failed'])}, skipped {len(results['skipped'])}",
                "method": self.pdf_converter.conversion_method
            }
            
        except Exception as error:
            log_sanitized_exception("Batch PDF conversion failed", error, logger=self.logger)
            return {
                "success": False,
                "error": "Batch PDF conversion failed - check server logs"
            }
    
    def get_status(self) -> Dict[str, Any]:
        """Get enhanced PDF conversion status"""
        return self.pdf_converter.get_conversion_status()


def create_enhanced_pdf_converter():
    """Factory function to create EnhancedPDFConverter"""
    return EnhancedPDFConverter()


def create_enhanced_pdf_api_handlers(
    reports_dir: Path,
    converter: Optional[EnhancedPDFConverter] = None,
):
    """Create API handlers, reusing an injected converter when provided."""
    converter = converter or create_enhanced_pdf_converter()
    return EnhancedPDFAPIHandlers(converter, reports_dir)
