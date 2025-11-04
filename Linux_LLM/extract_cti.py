import fitz  # pymupdf
import shutil
from pathlib import Path
import os
import traceback

SOURCE_DIR = Path.home() / "Desktop" / "2024"

def extract_all_pdfs_to_unified_folder():
    print(f"Searching for PDFs in source directory: {SOURCE_DIR}")
    
    # The base directory for finding source files is now SOURCE_DIR
    search_dir = SOURCE_DIR
    
    # The unified output folder is still created in the script's CURRENT LOCATION (Path.cwd())
    unified_folder = Path.cwd() / "all_pdfs"
    unified_folder.mkdir(exist_ok=True)
    
    print(f"Outputting extracted PDFs to: {unified_folder}")
    print("-" * 80)
    
    # Find all PDF files in Paper subfolders within the source directory
    pdf_count = 0
    # We use rglob(recursive glob) on the source directory
    for pdf_path in search_dir.rglob("Paper/*.pdf"):
        # Get the parent folder name (the report name)
        # Note: We assume the structure is: 2025/[ReportName]/Paper/*.pdf
        report_folder = pdf_path.parent.parent.name
        
        # Create a safe filename: use report folder name + original pdf name
        original_name = pdf_path.stem
        new_filename = f"{report_folder[:50]}_{original_name[:100]}.pdf"
        
        # Clean up the filename (remove invalid characters)
        new_filename = "".join(c if c.isalnum() or c in "._- " else "_" for c in new_filename)
        
        destination = unified_folder / new_filename
        
        # Copy the PDF
        try:
            shutil.copy2(pdf_path, destination)
            pdf_count += 1
            print(f"✓ Copied: {pdf_path.name}")
            print(f"  From: {report_folder}")
            print(f"  To: {new_filename}")
            print()
        except Exception as e:
            print(f"✗ Error copying {pdf_path.name}: {e}")
            print()
            
    print("-" * 80)
    print(f"Total PDFs extracted: {pdf_count}")
    print(f"Location: {unified_folder}")
    
    return unified_folder, pdf_count


def test_pymupdf_on_single_pdf(unified_folder):
    """
    Tests PyMuPDF capabilities on the first PDF found in the unified folder.
    """
    print("\n" + "=" * 80)
    print("TESTING PYMUPDF CAPABILITIES")
    print("=" * 80 + "\n")
    
    # Get the first PDF
    pdf_files = list(Path(unified_folder).glob("*.pdf"))
    
    if not pdf_files:
        print("No PDF files found to test!")
        return
    
    test_pdf = pdf_files[0]
    print(f"Testing with: {test_pdf.name}\n")
    
    try:
        # Open the PDF
        doc = fitz.open(test_pdf)
        
        # 1. Basic Information
        print("📄 BASIC INFORMATION")
        print("-" * 80)
        print(f"Number of pages: {len(doc)}")
        print(f"Is encrypted: {doc.is_encrypted}")
        print(f"Is PDF: {doc.is_pdf}")
        print(f"Needs pass: {doc.needs_pass}")
        
        # 2. Metadata
        print("\n📋 METADATA")
        print("-" * 80)
        metadata = doc.metadata
        for key, value in metadata.items():
            if value:
                print(f"{key}: {value}")
        
        # 3. First page information
        if len(doc) > 0:
            first_page = doc[0]
            print("\n📃 FIRST PAGE DETAILS")
            print("-" * 80)
            print(f"Page size: {first_page.rect.width} x {first_page.rect.height} points")
            print(f"Rotation: {first_page.rotation} degrees")
            
            # 4. Text extraction from first page
            print("\n📝 TEXT EXTRACTION (First 500 characters from page 1)")
            print("-" * 80)
            text = first_page.get_text()
            print(text[:500])
            if len(text) > 500:
                print(f"\n... [truncated, total {len(text)} characters]")
            
            # 5. Image detection
            print("\n🖼️  IMAGE DETECTION (First page)")
            print("-" * 80)
            image_list = first_page.get_images()
            print(f"Number of images on first page: {len(image_list)}")
            
            # 6. Links detection
            print("\n🔗 LINKS (First page)")
            print("-" * 80)
            links = first_page.get_links()
            print(f"Number of links on first page: {len(links)}")
            if links:
                print("First 3 links:")
                for i, link in enumerate(links[:3], 1):
                    if 'uri' in link:
                        print(f"  {i}. {link['uri']}")
            
            # 7. Table of Contents
            print("\n📚 TABLE OF CONTENTS")
            print("-" * 80)
            toc = doc.get_toc()
            if toc:
                print(f"Found {len(toc)} TOC entries")
                print("First 5 entries:")
                for level, title, page_num in toc[:5]:
                    indent = "  " * (level - 1)
                    print(f"{indent}[Page {page_num}] {title}")
            else:
                print("No table of contents found")
            
            # 8. Full text stats
            print("\n📊 FULL DOCUMENT TEXT STATISTICS")
            print("-" * 80)
            full_text = ""
            for page in doc:
                full_text += page.get_text()
            
            print(f"Total characters: {len(full_text):,}")
            print(f"Total words (approx): {len(full_text.split()):,}")
            print(f"Total lines: {len(full_text.splitlines()):,}")
        
        doc.close()
        
        print("\n" + "=" * 80)
        print("✓ PyMuPDF test completed successfully!")
        print("=" * 80)
        
    except Exception as e:
        print(f"\n✗ Error testing PDF: {e}")
        traceback.print_exc()


if __name__ == "__main__":
    # Step 1: Extract all PDFs
    unified_folder, count = extract_all_pdfs_to_unified_folder()
    
    # Step 2: Test PyMuPDF on one PDF
    if count > 0:
        test_pymupdf_on_single_pdf(unified_folder)
    else:
        print("\nNo PDFs found to test!")
