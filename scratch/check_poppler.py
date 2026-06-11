import sys
from pdf2image import convert_from_bytes

def test_pdf_conversion():
    # Create a dummy PDF header bytes
    dummy_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\nxref\n0 4\n0000000000 65535 f\n0000000009 00000 n\n0000000058 00000 n\n0000000115 00000 n\ntrailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n190\n%%EOF"
    
    try:
        convert_from_bytes(dummy_pdf)
        print("pdf2image check: SUCCESS (Poppler found)")
    except Exception as e:
        print(f"pdf2image check: FAILED. Error: {str(e)}")

if __name__ == "__main__":
    test_pdf_conversion()
