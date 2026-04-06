import argparse
import subprocess
import ipaddress
import socket
import requests
import os
import json
import csv
import platform
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

# Настройка логирования
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ==================== [ CONFIGURATION ] ====================
VERSION = "7.2"
TELEGRAM_TOKEN = os.getenv("TG_TOKEN", "YOUR_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TG_CHAT_ID", "YOUR_CHAT_ID")
CF_WORKER_URL = os.getenv("CF_WORKER", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK", "")

PORTS_TO_CHECK = {
    22: "SSH", 80: "HTTP", 443: "HTTPS",
    445: "SMB", 3389: "RDP", 8080: "WEB-Alt"
}

DEFAULT_THREADS = 60
# ==========================================================

BANNER = rf"""
  _____            _   _             _
 / ____|          | | (_)           | |
| (___   ___ _ __ | |_ _ _ __   ___| |
 \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
 ____) |  __/ | | | |_| | | | |  __/ |
|_____/ \___|_| |_|\__|_|_| |_|\___|_|
      ULTIMATE NETWORK SCANNER v{VERSION}
"""

def parse_arguments():
    parser = argparse.ArgumentParser(description=f"Sentinel v{VERSION} - Network Intelligence Tool")
    parser.add_argument("-n", "--network", help="Target subnet (e.g. 192.168.1.0/24)", required=True)
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"Threads (default: {DEFAULT_THREADS})")
    parser.add_argument("-f", "--format", choices=['json', 'csv'], help="Save results to file (json/csv)")
    parser.add_argument("--silent", action="store_true", help="Don't send any remote reports (TG/Slack)")
    return parser.parse_args()

def send_telegram(message):
    endpoints = []
    if CF_WORKER_URL:
        endpoints.append(f"{CF_WORKER_URL.rstrip('/')}/bot{TELEGRAM_TOKEN}/sendMessage")

    endpoints.extend([
        f"https://api.telegram-proxy.org/bot{TELEGRAM_TOKEN}/sendMessage",
        f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    ])

    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}

    for url in endpoints:
        try:
            r = requests.post(url, json=payload, timeout=10)
            if r.status_code == 200:
                return True
        except:
            continue
    return False

def send_slack(message):
    if not SLACK_WEBHOOK_URL:
        return False

    payload = {
        "text": message,
        "username": "Sentinel Scanner"
    }

    try:
        r = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=10)
        return r.status_code == 200
    except (requests.exceptions.RequestException, Exception):
        return False

def check_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            return port if s.connect_ex((ip, port)) == 0 else None
    except (ConnectionRefusedError, socket.timeout, OSError):
        return None

def scan_host(ip):
    ip_str = str(ip)
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        p = subprocess.run(['ping', param, '1', '-W', '1', ip_str],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if p.returncode == 0:
            try:
                name = socket.gethostbyaddr(ip_str)[0]
            except (socket.gaierror, socket.error, OSError):
                name = "no-name"

            found = [f"{port}({label})" for port, label in PORTS_TO_CHECK.items() if check_port(ip_str, port)]
            p_info = ", ".join(found) if found else "no open ports"

            return {
                "ip": ip_str, "name": name, "ports": p_info,
                "tg": f"• `{ip_str.ljust(15)}` | *{name[:12]}* | {p_info}"
            }
    except Exception as e:
        logger.warning(f"Host {ip_str} scan failed: {e}")
    return None

def main():
    load_dotenv()
    # Обновляем глобальные переменные после загрузки .env
    global TELEGRAM_TOKEN, TELEGRAM_CHAT_ID, CF_WORKER_URL, SLACK_WEBHOOK_URL
    TELEGRAM_TOKEN = os.getenv("TG_TOKEN", TELEGRAM_TOKEN)
    TELEGRAM_CHAT_ID = os.getenv("TG_CHAT_ID", TELEGRAM_CHAT_ID)
    CF_WORKER_URL = os.getenv("CF_WORKER", CF_WORKER_URL)
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK", SLACK_WEBHOOK_URL)

    args = parse_arguments()
    os.system('cls' if platform.system().lower() == 'windows' else 'clear')
    print(BANNER)

    try:
        network = ipaddress.ip_network(args.network, strict=False)
    except Exception as e:
        print(f"❌ Network Error: {e}")
        return

    print(f"[*] Scanning {network.num_addresses} hosts...")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = [r for r in list(executor.map(scan_host, network.hosts())) if r]

    if results:
        # Консольный вывод
        print(f"\n{'IP ADDRESS'.ljust(17)} | {'HOSTNAME'.ljust(15)} | SERVICES")
        print("-" * 65)
        for r in results:
            print(f"{r['ip'].ljust(17)} | {r['name'][:15].ljust(15)} | {r['ports']}")

        # Отправка отчетов
        if not args.silent:
            report_header = f"📡 *Sentinel v{VERSION} Report*\nTarget: `{args.network}`\n\n"
            report_body = "\n".join([r['tg'] for r in results])
            full_report = report_header + report_body + f"\n\n✅ Found: *{len(results)}*"

            if send_telegram(full_report):
                print("\n[+] Telegram report sent.")

            if SLACK_WEBHOOK_URL:
                if send_slack(full_report.replace("*", "")): # Slack не всегда любит MD-звездочки в таком виде
                    print("[+] Slack report sent.")

    else:
        print("\n[-] No active hosts detected.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted.")

