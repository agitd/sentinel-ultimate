import requests
from config.settings import TELEGRAM_TOKEN, TELEGRAM_CHAT_ID, CF_WORKER_URL, SLACK_WEBHOOK_URL

def send_notification(message: str, service: str = 'telegram') -> bool:
    if service == 'telegram':
        endpoints = [f"{CF_WORKER_URL.rstrip('/')}/bot{TELEGRAM_TOKEN}/sendMessage" if CF_WORKER_URL else None,
                     f"https://api.telegram-proxy.org/bot{TELEGRAM_TOKEN}/sendMessage",
                     f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"]
        endpoints = [e for e in endpoints if e]
        payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}
    else:
        endpoints = [SLACK_WEBHOOK_URL]
        payload = {"text": message, "username": "Sentinel Scanner"}

    for url in endpoints:
        try:
            r = requests.post(url, json=payload, timeout=10)
            if r.status_code in [200, 204]: return True
        except: continue
    return False

