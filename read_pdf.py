import PyPDF2
import sys

def read_pdf(filename):
    try:
        with open(filename, 'rb') as file:
            pdf_reader = PyPDF2.PdfReader(file)
            text = ""
            
            for page_num in range(len(pdf_reader.pages)):
                page = pdf_reader.pages[page_num]
                text += f"\n--- Sayfa {page_num + 1} ---\n"
                text += page.extract_text()
            
            return text
    except Exception as e:
        return f"Hata: {str(e)}"

if __name__ == "__main__":
    pdf_filename = "Bilgisayar Ağları Dönem Projesi.pdf"
    content = read_pdf(pdf_filename)
    print(content) 