import io
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
import PyPDF2
from PyPDF2 import PdfReader
from datetime import datetime


class PDFProcessor:
    """Handles PDF document text extraction"""
    
    @staticmethod
    def extract_text(file_content: bytes) -> str:
        """Extract text from PDF file content"""
        try:
            pdf_file = io.BytesIO(file_content)
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            text = ""
            
            for page_num, page in enumerate(pdf_reader.pages):
                try:
                    page_text = page.extract_text()
                    if page_text.strip():
                        text += f"\n--- Page {page_num + 1} ---\n"
                        text += page_text + "\n"
                except Exception as e:
                    print(f"⚠️ Error extracting page {page_num + 1}: {e}")
                    continue
            
            return text.strip()
        except Exception as e:
            print(f"⚠️ PDF extraction error: {e}")
            return ""
    
    @staticmethod
    def get_metadata(file_content: bytes) -> Dict[str, str]:
        """Extract PDF metadata"""
        try:
            pdf_file = io.BytesIO(file_content)
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            
            metadata = {}
            if pdf_reader.metadata:
                metadata.update({
                    'title': pdf_reader.metadata.get('/Title', ''),
                    'author': pdf_reader.metadata.get('/Author', ''),
                    'subject': pdf_reader.metadata.get('/Subject', ''),
                    'creator': pdf_reader.metadata.get('/Creator', ''),
                    'producer': pdf_reader.metadata.get('/Producer', ''),
                    'creation_date': str(pdf_reader.metadata.get('/CreationDate', '')),
                    'modification_date': str(pdf_reader.metadata.get('/ModDate', ''))
                })
            
            metadata['pages'] = len(pdf_reader.pages)
            return metadata
        except Exception as e:
            print(f"⚠️ PDF metadata extraction error: {e}")
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
        except:
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
        except:
            return False


class DocumentProcessor:
    """Processes uploaded documents for RAG integration"""
    
    def __init__(self, uploads_dir: str):
        self.uploads_dir = Path(uploads_dir)
        self.uploads_dir.mkdir(parents=True, exist_ok=True)
        self.supported_formats = {'.pdf', '.txt', '.md'}
    
    def process_upload(self, file_content: bytes, filename: str, save_to_disk: bool = True) -> Tuple[str, Dict[str, Any]]:
        """Process uploaded file and optionally save to disk"""
        file_path = Path(filename)
        file_ext = file_path.suffix.lower()
        
        if file_ext not in self.supported_formats:
            raise ValueError(f"Unsupported file format: {file_ext}")
        
        # Extract text based on file type
        if file_ext == '.pdf':
            text, metadata = self._process_pdf(file_content, filename)
        elif file_ext in {'.txt', '.md'}:
            text, metadata = self._process_text(file_content, filename)
        else:
            raise ValueError(f"Unsupported file format: {file_ext}")
        
        # Optionally save to disk
        if save_to_disk:
            saved_path = self._save_to_disk(text, filename, metadata)
            metadata['saved_path'] = str(saved_path)
            print(f"💾 Saved processed files to: {self.uploads_dir}")
        else:
            print(f"📄 Processed in memory only: {filename}")
        
        print(f"📄 Successfully processed: {filename} ({len(text)} chars)")
        return text, metadata
    
    def _process_pdf(self, file_content: bytes, filename: str) -> Tuple[str, Dict[str, Any]]:
        """Extract text from PDF content"""
        try:
            # Use BytesIO to read PDF from memory
            pdf_stream = io.BytesIO(file_content)
            reader = PdfReader(pdf_stream)
            
            text_parts = []
            for page_num, page in enumerate(reader.pages):
                try:
                    page_text = page.extract_text()
                    if page_text.strip():
                        text_parts.append(f"[Page {page_num + 1}]\n{page_text}")
                except Exception as e:
                    print(f"⚠️ Error extracting page {page_num + 1} from {filename}: {e}")
            
            full_text = "\n\n".join(text_parts)
            
            metadata = {
                'filename': filename,
                'type': 'pdf',
                'pages': len(reader.pages),
                'characters': len(full_text),
                'processed_at': datetime.now().isoformat()
            }
            
            return full_text, metadata
            
        except Exception as e:
            raise ValueError(f"Failed to process PDF {filename}: {str(e)}")
    
    def _process_text(self, file_content: bytes, filename: str) -> Tuple[str, Dict[str, Any]]:
        """Process text/markdown content"""
        try:
            # Try different encodings
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
        """Save processed text to disk"""
        # Create safe filename
        safe_filename = self._sanitize_filename(filename)
        base_name = Path(safe_filename).stem
        save_path = self.uploads_dir / f"{base_name}_processed.txt"
        
        # Ensure unique filename
        counter = 1
        while save_path.exists():
            save_path = self.uploads_dir / f"{base_name}_processed_{counter}.txt"
            counter += 1
        
        try:
            with open(save_path, 'w', encoding='utf-8') as f:
                # Write metadata header
                f.write(f"# Processed Document: {filename}\n")
                f.write(f"# Processed at: {metadata['processed_at']}\n")
                f.write(f"# Type: {metadata['type']}\n")
                if 'pages' in metadata:
                    f.write(f"# Pages: {metadata['pages']}\n")
                f.write(f"# Characters: {metadata['characters']}\n")
                f.write("\n" + "="*50 + "\n\n")
                f.write(text)
            
            return save_path
            
        except Exception as e:
            print(f"⚠️ Failed to save {filename}: {e}")
            raise
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe disk storage"""
        # Remove or replace unsafe characters
        unsafe_chars = '<>:"/\\|?*'
        safe_name = filename
        for char in unsafe_chars:
            safe_name = safe_name.replace(char, '_')
        return safe_name
    
    def get_processed_files(self) -> List[Dict[str, Any]]:
        """Get list of processed files on disk"""
        files = []
        
        if not self.uploads_dir.exists():
            return files
        
        for file_path in self.uploads_dir.glob("*_processed*.txt"):
            try:
                stat = file_path.stat()
                files.append({
                    'filename': file_path.name,
                    'path': str(file_path),
                    'size': stat.st_size,
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
