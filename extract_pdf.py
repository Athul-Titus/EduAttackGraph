import subprocess
import sys
import io

# Try to install pdfplumber if not available
try:
    import pdfplumber
except ImportError:
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pdfplumber'])
    import pdfplumber

pdf_path = "LLM-Assisted_Security_Vulnerability_Analysis_for_Educational_Websites_Risk_Identification_via_LLM-EduAttackGraph.pdf"

with open('paper_content.txt', 'w', encoding='utf-8') as out_file:
    with pdfplumber.open(pdf_path) as pdf:
        out_file.write(f"Total pages: {len(pdf.pages)}\n")
        print(f"Total pages: {len(pdf.pages)}")
        for i, page in enumerate(pdf.pages):
            text = page.extract_text()
            if text:
                header = f"\n{'='*60}\nPAGE {i+1}\n{'='*60}\n"
                out_file.write(header)
                out_file.write(text)
                out_file.write('\n')
                print(f"Extracted page {i+1}")

print('Done! Content saved to paper_content.txt')
