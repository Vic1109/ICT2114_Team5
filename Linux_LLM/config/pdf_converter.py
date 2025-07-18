import asyncio
import subprocess
import tempfile
import shutil
from pathlib import Path
from typing import Optional, Dict, Any, List, Union
from datetime import datetime
import logging
import re
import json


class EnhancedPDFConverter:
    """Enhanced PDF converter with better error handling and network fix"""
    
    def __init__(self):
        self.logger = logging.getLogger("EnhancedPDFConverter")
        self.logger.setLevel(logging.INFO)
        
        # Check available conversion methods
        self.conversion_method = self._detect_conversion_method()
        self.conversion_available = self.conversion_method != "none"
        
        self.logger.info(f"🔧 PDF conversion method: {self.conversion_method}")
    
    def _detect_conversion_method(self) -> str:
        """Detect which PDF conversion method is available"""
        # Check for WeasyPrint (preferred - pure Python, actively maintained)
        try:
            import weasyprint
            import markdown
            self.logger.info("✅ WeasyPrint available")
            return "weasyprint"
        except ImportError:
            pass
        
        # Check for pandoc with modern PDF engine
        if shutil.which("pandoc"):
            try:
                result = subprocess.run(
                    ["pandoc", "--version"], 
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    self.logger.info("✅ Pandoc available")
                    return "pandoc"
            except:
                pass
        
        # Check for basic markdown support
        try:
            import markdown
            self.logger.info("✅ Basic markdown available")
            return "markdown_html"
        except ImportError:
            pass
        
        self.logger.warning("⚠️ No PDF conversion method available")
        return "none"
    
    async def convert_markdown_to_pdf(self, markdown_path: Path, 
                                    output_dir: Optional[Path] = None,
                                    custom_css: Optional[str] = None) -> Optional[Path]:
        """Convert markdown file to PDF with enhanced error handling"""
        try:
            # Validate input
            if not markdown_path.exists():
                self.logger.error(f"❌ Markdown file not found: {markdown_path}")
                return None
            
            if not self.conversion_available:
                self.logger.error("❌ No PDF conversion method available")
                return None
            
            # Determine output path
            if output_dir is None:
                output_dir = markdown_path.parent
            
            output_path = output_dir / f"{markdown_path.stem}.pdf"
            
            # Convert based on available method
            success = False
            
            if self.conversion_method == "weasyprint":
                success = await self._convert_with_weasyprint(markdown_path, output_path, custom_css)
            elif self.conversion_method == "pandoc":
                success = await self._convert_with_pandoc(markdown_path, output_path)
            elif self.conversion_method == "markdown_html":
                success = await self._convert_with_html_fallback(markdown_path, output_path, custom_css)
            
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
        """Convert using WeasyPrint with enhanced error handling"""
        try:
            import weasyprint
            import markdown
            
            # Read markdown content
            with open(md_path, 'r', encoding='utf-8') as f:
                md_content = f.read()
            
            # Convert to HTML
            html_content = markdown.markdown(
                md_content,
                extensions=['tables', 'fenced_code', 'toc']
            )
            
            # Create full HTML document
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
            
            # Convert to PDF with error handling
            try:
                html_doc = weasyprint.HTML(string=full_html)
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
    
    async def _convert_with_pandoc(self, md_path: Path, pdf_path: Path) -> bool:
        """Convert using Pandoc with enhanced error handling"""
        try:
            cmd = [
                "pandoc",
                str(md_path),
                "-o", str(pdf_path),
                "--pdf-engine=pdflatex",
                "--variable", "geometry:margin=1in",
                "--variable", "fontsize=11pt",
                "--variable", "papersize=a4",
                "--toc",
                "--highlight-style=tango"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return True
            else:
                self.logger.error(f"Pandoc error: {stderr.decode()}")
                return False
                
        except Exception as e:
            self.logger.error(f"Pandoc conversion error: {e}")
            return False
    
    async def _convert_with_html_fallback(self, md_path: Path, pdf_path: Path, 
                                        custom_css: Optional[str] = None) -> bool:
        """Fallback conversion to HTML (when PDF not available)"""
        try:
            import markdown
            
            # Read markdown content
            with open(md_path, 'r', encoding='utf-8') as f:
                md_content = f.read()
            
            # Convert to HTML
            html_content = markdown.markdown(
                md_content,
                extensions=['tables', 'fenced_code', 'toc']
            )
            
            # Create full HTML document
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
            
            # Save as HTML instead of PDF
            html_path = pdf_path.with_suffix('.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(full_html)
            
            self.logger.info(f"📄 Created HTML report: {html_path.name} (PDF not available)")
            return True
            
        except Exception as e:
            self.logger.error(f"HTML fallback conversion error: {e}")
            return False
    
    def _get_default_css(self) -> str:
        """Enhanced CSS with proper line wrapping for PDF conversion"""
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
        
        /* Enhanced table styling with word wrapping */
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
            page-break-inside: avoid;
            table-layout: fixed;             /* Fixed layout for consistent column widths */
        }
        
        th, td {
            border: 1px solid #000000;
            padding: 12px;
            text-align: left;
            vertical-align: top;
            word-wrap: break-word;           /* Force word wrapping in cells */
            overflow-wrap: break-word;
            word-break: break-word;
            hyphens: auto;
            max-width: 0;                    /* Allow flexible column widths */
        }
        
        th {
            background-color: #000000;
            color: #ffffff;
            font-weight: bold;
            line-height: 1.3;
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
            
            # Run the async function
            try:
                # Check if we're already in an async context
                loop = asyncio.get_running_loop()
                # If we're in an async context, we need to handle this differently
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
                # No event loop running, create a new one
                asyncio.run(process_files())
            
            self.logger.info(f"📊 Batch conversion complete: {len(results['converted'])} converted, "
                           f"{len(results['failed'])} failed, {len(results['skipped'])} skipped")
            
        except Exception as e:
            self.logger.error(f"❌ Batch conversion error: {e}")
            results["errors"].append(f"Batch conversion error: {str(e)}")
        
        return results
    
    def get_conversion_status(self) -> Dict[str, Any]:
        """Get enhanced conversion method and capabilities"""
        status = {
            "method": self.conversion_method,
            "available": self.conversion_available,
            "capabilities": self._check_capabilities(),
            "recommendations": []
        }
        
        # Add recommendations based on available tools
        if not self.conversion_available:
            status["recommendations"].extend([
                "Install WeasyPrint: pip install weasyprint",
                "Install Pandoc: apt-get install pandoc texlive-latex-base",
                "Install markdown: pip install markdown"
            ])
        elif self.conversion_method == "markdown_html":
            status["recommendations"].append(
                "Install WeasyPrint or Pandoc for proper PDF conversion"
            )
        
        return status
    
    def _check_capabilities(self) -> Dict[str, bool]:
        """Check availability of conversion dependencies"""
        capabilities = {}
        
        # Check Python libraries
        try:
            import weasyprint
            capabilities["weasyprint"] = True
        except ImportError:
            capabilities["weasyprint"] = False
        
        try:
            import markdown
            capabilities["markdown"] = True
        except ImportError:
            capabilities["markdown"] = False
        
        # Check command-line tools
        capabilities["pandoc"] = shutil.which("pandoc") is not None
        capabilities["pdflatex"] = shutil.which("pdflatex") is not None
        
        return capabilities


# Enhanced API handlers for FastAPI integration
class EnhancedPDFAPIHandlers:
    """Enhanced API handlers with proper error handling"""
    
    def __init__(self, pdf_converter: EnhancedPDFConverter, reports_dir: Path):
        self.pdf_converter = pdf_converter
        self.reports_dir = reports_dir
        self.logger = logging.getLogger("EnhancedPDFAPI")
    
    async def handle_single_conversion(self, filename: str) -> Dict[str, Any]:
        """Handle single file conversion with enhanced error handling"""
        try:
            # Validate filename
            if not filename or not filename.endswith('.md'):
                return {
                    "success": False,
                    "error": "Invalid filename - must be a .md file"
                }
            
            md_path = self.reports_dir / filename
            
            if not md_path.exists():
                return {
                    "success": False,
                    "error": f"Markdown report not found: {filename}"
                }
            
            # Check conversion availability
            if not self.pdf_converter.conversion_available:
                return {
                    "success": False,
                    "error": "PDF conversion not available - check system dependencies",
                    "recommendations": self.pdf_converter.get_conversion_status()["recommendations"]
                }
            
            # Perform conversion
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
            # Check conversion availability
            if not self.pdf_converter.conversion_available:
                return {
                    "success": False,
                    "error": "PDF conversion not available - check system dependencies",
                    "recommendations": self.pdf_converter.get_conversion_status()["recommendations"]
                }
            
            # Perform batch conversion
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


# Factory function for easy integration
def create_enhanced_pdf_converter():
    """Factory function to create EnhancedPDFConverter"""
    return EnhancedPDFConverter()


def create_enhanced_pdf_api_handlers(reports_dir: Path):
    """Factory function to create enhanced PDF API handlers"""
    converter = create_enhanced_pdf_converter()
    return EnhancedPDFAPIHandlers(converter, reports_dir)