import io
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Any
import PyPDF2


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
    """Main document processing orchestrator"""
    
    def __init__(self, upload_dir: str = None):
        self.upload_dir = Path(upload_dir) if upload_dir else None
        self.pdf_processor = PDFProcessor()
        self.text_processor = TextProcessor()
        self.markdown_processor = MarkdownProcessor()
        self.validator = DocumentValidator()
    
    def process_upload(self, file_content: bytes, filename: str, 
                      save_to_disk: bool = False) -> Tuple[str, Dict[str, Any]]:
        """
        Process uploaded file and extract text
        
        Returns:
            Tuple of (extracted_text, metadata)
        """
        try:
            # Validate file
            is_valid, validation_msg = self.validator.validate_file(filename, file_content)
            if not is_valid:
                print(f"❌ File validation failed: {validation_msg}")
                return "", {"error": validation_msg, "filename": filename}
            
            # Extract text based on file type
            file_ext = Path(filename).suffix.lower()
            extracted_text = ""
            metadata = {
                "filename": filename,
                "file_size": len(file_content),
                "file_type": file_ext,
                "processed_at": str(os.getcwd()),
                "success": False
            }
            
            if file_ext == '.pdf':
                extracted_text = self.pdf_processor.extract_text(file_content)
                pdf_metadata = self.pdf_processor.get_metadata(file_content)
                metadata.update(pdf_metadata)
            
            elif file_ext in ['.txt']:
                encoding = self.text_processor.detect_encoding(file_content)
                extracted_text = self.text_processor.extract_text(file_content, encoding)
                metadata['encoding'] = encoding
            
            elif file_ext in ['.md', '.markdown']:
                extracted_text = self.markdown_processor.extract_text(file_content)
                metadata['preserve_structure'] = True
            
            else:
                error_msg = f"Unsupported file type: {file_ext}"
                print(f"⚠️ {error_msg}")
                metadata['error'] = error_msg
                return "", metadata
            
            # Update metadata
            metadata.update({
                "success": bool(extracted_text.strip()),
                "text_length": len(extracted_text),
                "word_count": len(extracted_text.split()) if extracted_text else 0
            })
            
            # Save to disk if requested
            if save_to_disk and self.upload_dir and extracted_text:
                self._save_processed_file(filename, file_content, extracted_text, metadata)
            
            if extracted_text:
                print(f"📄 Successfully processed: {filename} ({len(extracted_text)} chars)")
            else:
                print(f"⚠️ No text extracted from: {filename}")
            
            return extracted_text, metadata
            
        except Exception as e:
            error_msg = f"Processing error: {str(e)}"
            print(f"❌ {error_msg}")
            return "", {
                "filename": filename,
                "error": error_msg,
                "success": False
            }
    
    def process_multiple(self, files: List[Tuple[bytes, str]], 
                        save_to_disk: bool = False) -> List[Tuple[str, Dict[str, any]]]:
        """Process multiple files"""
        results = []
        
        for file_content, filename in files:
            text, metadata = self.process_upload(file_content, filename, save_to_disk)
            results.append((text, metadata))
        
        successful = sum(1 for _, meta in results if meta.get('success', False))
        print(f"📊 Processed {len(files)} files: {successful} successful, {len(files) - successful} failed")
        
        return results
    
    def _save_processed_file(self, filename: str, original_content: bytes, 
                           extracted_text: str, metadata: Dict[str, any]):
        """Save processed file and metadata to disk"""
        try:
            if not self.upload_dir:
                return
            
            # Ensure upload directory exists
            self.upload_dir.mkdir(parents=True, exist_ok=True)
            
            # Save original file
            original_path = self.upload_dir / filename
            with open(original_path, 'wb') as f:
                f.write(original_content)
            
            # Save extracted text
            text_filename = f"{Path(filename).stem}_extracted.txt"
            text_path = self.upload_dir / text_filename
            with open(text_path, 'w', encoding='utf-8') as f:
                f.write(extracted_text)
            
            # Save metadata
            metadata_filename = f"{Path(filename).stem}_metadata.json"
            metadata_path = self.upload_dir / metadata_filename
            import json
            with open(metadata_path, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2, default=str)
            
            print(f"💾 Saved processed files to: {self.upload_dir}")
            
        except Exception as e:
            print(f"⚠️ Error saving processed file: {e}")
    
    def get_supported_types(self) -> Dict[str, int]:
        """Get supported file types and their size limits"""
        return self.validator.SUPPORTED_TYPES.copy()
    
    def validate_files(self, files: List[Tuple[bytes, str]]) -> Dict[str, List[str]]:
        """Validate multiple files and return validation results"""
        results = {
            "valid": [],
            "invalid": [],
            "errors": []
        }
        
        for file_content, filename in files:
            is_valid, message = self.validator.validate_file(filename, file_content)
            if is_valid:
                results["valid"].append(filename)
            else:
                results["invalid"].append(filename)
                results["errors"].append(f"{filename}: {message}")
        
        return results


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
