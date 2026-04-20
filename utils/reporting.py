import json
import csv
import logging
from datetime import datetime
from config import settings  # Добавил импорт настроек
import ai_analyze  # Добавил импорт нового (будущего) модуля

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

    # Заголовок
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, f"Sentinel Network Audit: {network}", ln=True, align='C')
    pdf.set_font("Arial", '', 10)
    pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M')}", ln=True)
    pdf.ln(10)

    # Таблица результатов
    pdf.set_font("Arial", 'B', 10)
    pdf.cell(40, 10, "IP Address", 1)
    pdf.cell(50, 10, "Hostname", 1)
    pdf.cell(100, 10, "Ports & OS", 1)
    pdf.ln()

    pdf.set_font("Arial", '', 9)
    # краткий текст для нейронки прямо во время отрисовки таблицы
    scan_summary = []

    for r in results:
        ip = str(r.get('ip', 'unk'))
        name = str(r.get('name', 'unk'))
        os_info = str(r.get('os', 'unk'))
        ports = str(r.get('ports', 'unk'))

        pdf.cell(40, 10, ip, 1)
        pdf.cell(50, 10, name[:20], 1)
        pdf.cell(100, 10, f"{os_info} | {ports}"[:55], 1)
        pdf.ln()

        # Наполнение данных для ИИ
        scan_summary.append(f"Host: {ip} ({name}), OS: {os_info}, Ports: {ports}")

    # --- НОВЫЙ БЛОК: AI ANALYSIS ---
    if settings.AI_ENABLED:
        pdf.ln(10)
        pdf.set_font("Arial", 'B', 12)
        pdf.cell(0, 10, "AI Security Analysis", ln=True)
        pdf.set_font("Arial", 'I', 9)

        print(f"[*] Отправка данных ({len(scan_summary)} хостов) на анализ ИИ...")

        # Объединяем данные в один текст и шлет в ai_analyze
        full_text_for_ai = "\n".join(scan_summary)
        ai_opinion = ai_analyze.ask_ai_analysis(full_text_for_ai)

        if ai_opinion:
            # Используем multi_cell, так как ответ от ИИ будет длинным
            pdf.multi_cell(0, 5, ai_opinion)
        else:
            pdf.cell(0, 10, "AI Analysis failed or returned no data.", ln=True)
    # -------------------------------

    pdf.output(filename)
    print(f"[+] Отчет сохранен: {filename}")

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
