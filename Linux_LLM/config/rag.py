import io
import os
from pathlib import Path
from typing import List, Dict, Tuple, Any
from datetime import datetime
import pymupdf  # PyMuPDF
import hashlib
from cti_artifacts import CTIArtifactExtractor

class PDFProcessor:
    """Handles PDF document text extraction"""
    
    @staticmethod
    def extract_text(file_content: bytes) -> str:
        """Extract text with table detection"""
        try:
            pdf_stream = io.BytesIO(file_content)
            doc = pymupdf.open(stream=pdf_stream, filetype="pdf")
            
            full_text = []
            
            for page_num in range(len(doc)):
                page = doc[page_num]
                
                # Extract text blocks (preserves layout)
                blocks = page.get_text("blocks")
                
                page_text = f"\n--- Page {page_num + 1} ---\n"
                for block in blocks:
                    # block[4] is the text content
                    if block[4].strip():
                        page_text += block[4] + "\n"
                
                # Extract tables if present
                tables = page.find_tables()
                if tables:
                    page_text += "\n[TABLES DETECTED]\n"
                    for table in tables:
                        page_text += table.to_markdown() + "\n"

                links = [link["uri"] for link in page.get_links() if "uri" in link]
                if links:
                    page_text += "\n[LINKS DETECTED]\n"
                    page_text += "\n".join(links) + "\n"

                image_count = len(page.get_images())
                if image_count:
                    page_text += f"\n[IMAGES DETECTED: {image_count} image(s) on this page; OCR not performed]\n"
                
                full_text.append(page_text)
            
            doc.close()
            return "\n".join(full_text)
            
        except Exception as e:
            print(f"⚠️ pymupdf extraction error: {e}")
            return ""
    
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
            print(f"⚠️ Metadata extraction error: {e}")
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
            print(f"⚠️ Structure extraction error: {e}")
            return {}


class TextProcessor:
    """Handles plain text file processing"""
    
    @staticmethod
    def extract_text(file_content: bytes, encoding: str = 'utf-8') -> str:
        """Extract text from plain text files"""
        try:
            return file_content.decode(encoding, errors='ignore').strip()
        except Exception as e:
            print(f"⚠️ Text extraction error: {e}")
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
            print(f"⚠️ Markdown extraction error: {e}")
            return ""


class DocumentValidator:
    """Validates documents for security and content quality"""
    
    # Supported file types and their max sizes (in MB)
    SUPPORTED_TYPES = {
        '.pdf': 10,
        '.txt': 5,
        '.md': 5,
        '.markdown': 5
    }
    
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
        self.supported_formats = {'.pdf', '.txt', '.md', '.markdown'}
        self.processed_hashes = set()  # Track processed file hashes in memory
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
                            self.processed_hashes.add(hash_value)
                            break
            except Exception:
                pass
    
    def check_duplicate(self, file_content: bytes, filename: str) -> Tuple[bool, str]:
        """Check if file content is a duplicate"""
        content_hash = hashlib.sha256(file_content).hexdigest()
        
        if content_hash in self.processed_hashes:
            return True, f"⚠️ Duplicate detected: '{filename}' has already been processed (hash: {content_hash[:16]}...)"
        
        return False, content_hash
    
    def process_upload(self, file_content: bytes, filename: str, save_to_disk: bool = True) -> Tuple[str, Dict[str, Any]]:
        """Process uploaded file with duplicate detection"""
        is_valid, validation_message = DocumentValidator.validate_file(filename, file_content)
        if not is_valid:
            raise ValueError(validation_message)

        file_path = Path(filename)
        file_ext = file_path.suffix.lower()
        
        if file_ext not in self.supported_formats:
            raise ValueError(f"Unsupported file format: {file_ext}")
        
        # Check for duplicates
        is_duplicate, hash_or_message = self.check_duplicate(file_content, filename)
        if is_duplicate:
            raise ValueError(hash_or_message)  # Raise error with duplicate message
        
        content_hash = hash_or_message
        
        # Extract text based on file type
        if file_ext == '.pdf':
            # PyMuPDF preserves layout and tables better for these reports.
            text = PDFProcessor.extract_text(file_content)
            pdf_metadata = PDFProcessor.get_metadata(file_content)
            
            artefacts = CTIArtifactExtractor.extract(text)
            metadata = {
                'filename': filename,
                'type': 'pdf',
                'pages': pdf_metadata.get('pages', 0),
                'characters': len(text),
                'content_hash': content_hash,
                'processed_at': datetime.now().isoformat(),
                'cti_artifacts': artefacts,
                'artifact_counts': CTIArtifactExtractor.count_by_type(artefacts)
            }
            
            # Add PDF-specific metadata
            if pdf_metadata.get('title'):
                metadata['pdf_title'] = pdf_metadata['title']
            if pdf_metadata.get('author'):
                metadata['pdf_author'] = pdf_metadata['author']
            
        elif file_ext in {'.txt', '.md', '.markdown'}:
            text, metadata = self._process_text(file_content, filename)
            metadata['content_hash'] = content_hash
            artefacts = CTIArtifactExtractor.extract(text)
            metadata['cti_artifacts'] = artefacts
            metadata['artifact_counts'] = CTIArtifactExtractor.count_by_type(artefacts)
        else:
            raise ValueError(f"Unsupported file format: {file_ext}")
        
        # Optionally save to disk
        if save_to_disk:
            saved_path = self._save_to_disk(text, filename, metadata)
            metadata['saved_path'] = str(saved_path)
            self.processed_hashes.add(content_hash)
            print(f"💾 Saved processed file: {saved_path.name}")
        else:
            print(f"📄 Processed in memory only: {filename}")
        
        print(f"✅ Successfully processed: {filename} ({len(text)} chars, hash: {content_hash[:16]}...)")
        self.processed_hashes.add(content_hash)
        return text, metadata
    
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
            print(f"⚠️ Failed to save {filename}: {e}")
            raise
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe disk storage"""
        unsafe_chars = '<>:"/\\|*'
        safe_name = filename
        for char in unsafe_chars:
            safe_name = safe_name.replace(char, '_')
        return safe_name
    
    def get_processed_files(self) -> List[Dict[str, Any]]:
        """Get list of processed files with hash information"""
        files = []
        
        if not self.uploads_dir.exists():
            return files
        
        for file_path in self.uploads_dir.glob("*_processed*.txt"):
            try:
                stat = file_path.stat()
                
                # Extract hash from file
                content_hash = None
                with open(file_path, 'r', encoding='utf-8') as f:
                    for _ in range(10):
                        line = f.readline()
                        if line.startswith("# Content Hash:"):
                            content_hash = line.split(":")[1].strip()
                            break
                
                files.append({
                    'filename': file_path.name,
                    'path': str(file_path),
                    'size': stat.st_size,
                    'content_hash': content_hash,
                    'modified': datetime.fromtimestamp(stat.st_mtime).isoformat()
                })
            except Exception as e:
                print(f"⚠️ Error reading file info for {file_path}: {e}")
        
        return sorted(files, key=lambda x: x['modified'], reverse=True)
    
    def cleanup_old_files(self, max_age_days: int = 7) -> int:
        """Clean up old processed files"""
        if not self.uploads_dir.exists():
            return 0
        
        cutoff_time = datetime.now().timestamp() - (max_age_days * 24 * 3600)
        deleted_count = 0
        
        for file_path in self.uploads_dir.glob("*_processed*.txt"):
            try:
                if file_path.stat().st_mtime < cutoff_time:
                    file_path.unlink()
                    deleted_count += 1
            except Exception as e:
                print(f"⚠️ Error deleting old file {file_path}: {e}")
        
        if deleted_count > 0:
            print(f"🧹 Cleaned up {deleted_count} old processed files")
        
        return deleted_count


# Utility functions for backward compatibility
def extract_text_from_pdf(file_content: bytes) -> str:
    """Legacy function for PDF text extraction"""
    return PDFProcessor.extract_text(file_content)


def process_upload(file_content: bytes, filename: str) -> str:
    """Legacy function for document processing"""
    processor = DocumentProcessor()
    text, metadata = processor.process_upload(file_content, filename)
    return text


# Factory function for easy initialization
def create_document_processor(upload_dir: str = None) -> DocumentProcessor:
    """Factory function to create DocumentProcessor with default settings"""
    return DocumentProcessor(upload_dir)


# Configuration class for document processing settings
class DocumentProcessingConfig:
    """Configuration for document processing"""
    
    def __init__(self):
        self.max_file_size_mb = 10
        self.supported_extensions = ['.pdf', '.txt', '.md', '.markdown']
        self.default_encoding = 'utf-8'
        self.preserve_markdown_structure = True
        self.enable_metadata_extraction = True
        self.save_processed_files = False
        self.upload_directory = None
    
    def update_supported_types(self, new_types: Dict[str, int]):
        """Update supported file types and their size limits"""
        DocumentValidator.SUPPORTED_TYPES.update(new_types)
    
    def validate_config(self) -> Tuple[bool, str]:
        """Validate configuration settings"""
        if self.max_file_size_mb <= 0:
            return False, "Max file size must be positive"
        
        if not self.supported_extensions:
            return False, "At least one file extension must be supported"
        
        if self.upload_directory and not os.path.exists(self.upload_directory):
            try:
                os.makedirs(self.upload_directory, exist_ok=True)
            except Exception as e:
                return False, f"Cannot create upload directory: {e}"
        
        return True, "Configuration is valid"
