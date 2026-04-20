import requests
import json
import sys
import os

# Добавил путь к корню проекта, чтобы Python нашел папку config
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    from config.settings import AI_API_URL, AI_MODEL, AI_ENABLED
except ImportError:
    # Если запуск идет из корня, сработает этот вариант
    from config.settings import AI_API_URL, AI_MODEL, AI_ENABLED

def ask_ai_analysis(scan_data):
    """
    Отправляет собранные данные сканирования в локальную нейронку (Ollama).
    """
    if not AI_ENABLED:
        return None

    prompt = (
        "Ты - профессиональный эксперт по кибербезопасности и пентесту. "
        "Проанализируй следующие данные сканирования сети. "
        "Найди критические уязвимости, устаревшие сервисы или опасные открытые порты. "
        "Дай краткий, технический вердикт и предложи шаги по защите. "
        "Данные сканирования:\n"
        f"{scan_data}\n\n"
        "Твой вердикт:"
    )

    payload = {
        "model": AI_MODEL,
        "prompt": prompt,
        "stream": False
    }

    try:
        # Для локальной Ламы 30 секунд может быть маловато, если проц слабый.
        # Если будет отваливаться по таймауту - поставь 60.
        response = requests.post(AI_API_URL, json=payload, timeout=300)
        response.raise_for_status()

        result = response.json().get('response', '')
        return result.strip()

    except requests.exceptions.RequestException as e:
        print(f"\n[!] Ошибка связи с ИИ: {e}")
        return f"AI Analysis failed: {str(e)}"

