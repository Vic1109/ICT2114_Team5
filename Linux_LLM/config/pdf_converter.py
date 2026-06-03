import asyncio
from pathlib import Path
from typing import Optional, Dict, Any
import logging
import re

WEASYPRINT_IMPORT_ERROR = None
MARKDOWN_IMPORT_ERROR = None

try:
    import weasyprint
except Exception as exc:
    weasyprint = None
    WEASYPRINT_IMPORT_ERROR = str(exc)

try:
    import markdown
except Exception as exc:
    markdown = None
    MARKDOWN_IMPORT_ERROR = str(exc)


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
            self.logger.warning(f" WeasyPrint unavailable: {WEASYPRINT_IMPORT_ERROR}")
        if MARKDOWN_IMPORT_ERROR:
            self.logger.warning(f" markdown unavailable: {MARKDOWN_IMPORT_ERROR}")
        self.logger.warning(" No PDF conversion method available")
        return "none"
    
    async def convert_markdown_to_pdf(self, markdown_path: Path, 
                                    output_dir: Optional[Path] = None,
                                    custom_css: Optional[str] = None) -> Optional[Path]:
        try:
            # Validate input
            if not markdown_path.exists():
                self.logger.error(f"❌ Markdown file not found: {markdown_path}")
                return None
            
            if not self.conversion_available:
                self.logger.error("❌ No PDF conversion method available")
                return None
            
            if output_dir is None:
                output_dir = markdown_path.parent
            
            output_path = output_dir / f"{markdown_path.stem}.pdf"
            
            success = False
            
            if self.conversion_method == "weasyprint":
                success = await self._convert_with_weasyprint(markdown_path, output_path, custom_css)
            
            if success and output_path.exists():
                self.logger.info(f"✅ PDF created: {output_path.name}")
                return output_path
            else:
                self.logger.error(f"❌ PDF conversion failed for {markdown_path.name}")
                return None
                
        except Exception as e:
            self.logger.error(f"❌ Error converting {markdown_path.name} to PDF: {e}")
            return None
    
    async def _convert_with_weasyprint(self, md_path: Path, pdf_path: Path, 
                                     custom_css: Optional[str] = None) -> bool:
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
                import re
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
            
            try:
                html_doc = weasyprint.HTML(string=full_html, base_url=str(md_path.parent))
                html_doc.write_pdf(str(pdf_path))
                return True
            except Exception as e:
                self.logger.error(f"WeasyPrint conversion error: {e}")
                return False
            
        except ImportError as e:
            self.logger.error(f"WeasyPrint not available: {e}")
            return False
        except Exception as e:
            self.logger.error(f"WeasyPrint conversion error: {e}")
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
    
    def batch_convert_reports(self, reports_dir: Path, 
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
            
            markdown_files = list(reports_dir.glob(pattern))
            results["total_processed"] = len(markdown_files)
            
            if not markdown_files:
                results["errors"].append("No markdown files found")
                return results
            
            # Process files asynchronously
            async def process_files():
                for md_file in markdown_files:
                    try:
                        # Skip if PDF already exists and is newer
                        pdf_file = md_file.with_suffix('.pdf')
                        if (pdf_file.exists() and 
                            pdf_file.stat().st_mtime > md_file.stat().st_mtime):
                            results["skipped"].append(md_file.name)
                            continue
                        
                        # Convert to PDF
                        pdf_path = await self.convert_markdown_to_pdf(md_file, reports_dir)
                        
                        if pdf_path:
                            results["converted"].append(pdf_path.name)
                        else:
                            results["failed"].append(md_file.name)
                            
                    except Exception as e:
                        results["failed"].append(md_file.name)
                        results["errors"].append(f"{md_file.name}: {str(e)}")
            
            try:
                loop = asyncio.get_running_loop()
                import concurrent.futures
                import threading
                
                def run_in_thread():
                    new_loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(new_loop)
                    try:
                        new_loop.run_until_complete(process_files())
                    finally:
                        new_loop.close()
                
                thread = threading.Thread(target=run_in_thread)
                thread.start()
                thread.join()
                
            except RuntimeError:
                asyncio.run(process_files())
            
            self.logger.info(f" Batch conversion complete: {len(results['converted'])} converted, "
                           f"{len(results['failed'])} failed, {len(results['skipped'])} skipped")
            
        except Exception as e:
            self.logger.error(f"❌ Batch conversion error: {e}")
            results["errors"].append(f"Batch conversion error: {str(e)}")
        
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
                status["weasyprint_error"] = WEASYPRINT_IMPORT_ERROR
            if MARKDOWN_IMPORT_ERROR:
                status["markdown_error"] = MARKDOWN_IMPORT_ERROR
        
        return status
    
    def _check_capabilities(self) -> Dict[str, Any]:
        capabilities = {}
        
        capabilities["weasyprint"] = weasyprint is not None
        capabilities["markdown"] = markdown is not None
        capabilities["weasyprint_error"] = WEASYPRINT_IMPORT_ERROR
        capabilities["markdown_error"] = MARKDOWN_IMPORT_ERROR
        
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
                
        except Exception as e:
            self.logger.error(f"❌ Single conversion error: {e}")
            return {
                "success": False,
                "error": f"Conversion error: {str(e)}"
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
            
            results = self.pdf_converter.batch_convert_reports(self.reports_dir)
            
            return {
                "success": True,
                "results": results,
                "summary": f"Converted {len(results['converted'])}, failed {len(results['failed'])}, skipped {len(results['skipped'])}",
                "method": self.pdf_converter.conversion_method
            }
            
        except Exception as e:
            self.logger.error(f"❌ Batch conversion error: {e}")
            return {
                "success": False,
                "error": f"Batch conversion error: {str(e)}"
            }
    
    def get_status(self) -> Dict[str, Any]:
        """Get enhanced PDF conversion status"""
        return self.pdf_converter.get_conversion_status()


def create_enhanced_pdf_converter():
    """Factory function to create EnhancedPDFConverter"""
    return EnhancedPDFConverter()


def create_enhanced_pdf_api_handlers(reports_dir: Path):
    """Factory function to create enhanced PDF API handlers"""
    converter = create_enhanced_pdf_converter()
    return EnhancedPDFAPIHandlers(converter, reports_dir)
