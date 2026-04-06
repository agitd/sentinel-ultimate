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
VERSION = "8.5"  # ОБНОВИЛИ!
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
        except (requests.exceptions.RequestException, Exception):
            logger.warning(f"Failed to send Telegram to {url}")
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
        logger.warning("Failed to send Slack report")
        return False

def check_port(ip, port):
    """Проверка открытого порта"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            return port if s.connect_ex((ip, port)) == 0 else None
    except (ConnectionRefusedError, socket.timeout, OSError):
        return None

def get_service_version(ip, port):
    """Получить версию сервиса через banner grabbing"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))

        # Для HTTP сервисов - отправляем HEAD запрос
        if port in [80, 8080, 8000, 8888]:
            try:
                s.send(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                banner = s.recv(1024).decode('utf-8', errors='ignore')
                # Ищем Server header
                for line in banner.split('\n'):
                    if 'Server:' in line:
                        s.close()
                        version = line.replace('Server:', '').strip()[:40]
                        return version if version else "unknown"
            except (socket.timeout, Exception):
                pass

        # Для остальных сервисов - читаем первый ответ
        try:
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()

            if banner:
                # Берем первую непустую строку
                first_line = banner.split('\n')[0].strip()
                version = first_line[:40] if first_line else "unknown"
                return version
        except (socket.timeout, Exception):
            s.close()

        return "unknown"

    except socket.timeout:
        return "timeout"
    except ConnectionRefusedError:
        return "refused"
    except (socket.gaierror, socket.error, OSError) as e:
        logger.debug(f"Banner grab error for {ip}:{port} - {e}")
        return "error"

def scan_host(ip):
    """Сканирование одного хоста с получением версий"""
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

            # Сканируем портов и получаем версии
            found = []
            for port, label in PORTS_TO_CHECK.items():
                if check_port(ip_str, port):
                    version = get_service_version(ip_str, port)
                    # Добавляем версию если она не "unknown" или "error"
                    if version and version not in ["unknown", "timeout", "refused", "error"]:
                        found.append(f"{port}({label}/{version})")
                    else:
                        found.append(f"{port}({label})")

            p_info = ", ".join(found) if found else "no open ports"

            return {
                "ip": ip_str,
                "name": name,
                "ports": p_info,
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

    print(f"[*] Scanning {network.num_addresses} hosts with version detection...")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = [r for r in list(executor.map(scan_host, network.hosts())) if r]

    if results:
        # Консольный вывод
        print(f"\n{'IP ADDRESS'.ljust(17)} | {'HOSTNAME'.ljust(15)} | SERVICES")
        print("-" * 100)
        for r in results:
            print(f"{r['ip'].ljust(17)} | {r['name'][:15].ljust(15)} | {r['ports']}")

        # Экспорт результатов
        if args.format == "json":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_{timestamp}.json"
            output = {
                "scan_metadata": {
                    "version": VERSION,
                    "timestamp": datetime.now().isoformat(),
                    "os_platform": platform.system(),
                    "total_found": len(results)
                },
                "hosts": results
            }
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(output, f, indent=4, ensure_ascii=False)
                print(f"\n[+] JSON exported to {filename}")
            except Exception as e:
                logger.error(f"Failed to save JSON: {e}")

        elif args.format == "csv":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_{timestamp}.csv"
            try:
                with open(filename, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=["ip", "name", "ports"])
                    writer.writeheader()
                    writer.writerows(results)
                print(f"\n[+] CSV exported to {filename}")
            except Exception as e:
                logger.error(f"Failed to save CSV: {e}")

        # Отправка отчетов
        if not args.silent:
            report_header = f"📡 *Sentinel v{VERSION} Report*\nTarget: `{args.network}`\n\n"
            report_body = "\n".join([r['tg'] for r in results])
            full_report = report_header + report_body + f"\n\n✅ Found: *{len(results)}*"

            if send_telegram(full_report):
                print("[+] Telegram report sent.")

            if SLACK_WEBHOOK_URL:
                if send_slack(full_report.replace("*", "")):
                    print("[+] Slack report sent.")

    else:
        print("\n[-] No active hosts detected.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted.")
