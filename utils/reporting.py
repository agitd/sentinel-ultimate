import json
import csv
import logging
from datetime import datetime

try:
    from fpdf import FPDF
except ImportError:
    try:
        from fpdf2 import FPDF
    except ImportError:
        FPDF = None

class SentinelPDF:
    def __init__(self):
        if FPDF is None:
            raise ImportError("Библиотека fpdf2 не найдена. Установи ее: pip install fpdf2")
        self.pdf = FPDF()

def generate_pdf_report(results, network, filename):
    if FPDF is None:
        print("[-] Ошибка: PDF не может быть создан без библиотеки fpdf2.")
        return

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, f"Sentinel Network Audit: {network}", ln=True, align='C')
    pdf.set_font("Arial", '', 10)
    pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=True)
    pdf.ln(10)

    pdf.set_font("Arial", 'B', 10)
    pdf.cell(40, 10, "IP Address", 1)
    pdf.cell(50, 10, "Hostname", 1)
    pdf.cell(100, 10, "Ports & OS", 1)
    pdf.ln()

    pdf.set_font("Arial", '', 9)
    for r in results:
        pdf.cell(40, 10, str(r.get('ip', 'unk')), 1)
        pdf.cell(50, 10, str(r.get('name', 'unk'))[:20], 1)
        pdf.cell(100, 10, f"{r.get('os', 'unk')} | {r.get('ports', 'unk')}"[:55], 1)
        pdf.ln()

    pdf.output(filename)

def export_to_json(results, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=4)

def export_to_csv(results, filename):
    if not results: return
    keys = results[0].keys()
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        dict_writer = csv.DictWriter(f, fieldnames=keys)
        dict_writer.writeheader()
        dict_writer.writerows(results)

