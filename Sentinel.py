import argparse
import subprocess
import ipaddress
import socket
import requests
import os
import json
import csv
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv  # Добавлено: импорт для работы с .env

# ==================== [ CONFIGURATION ] ====================
VERSION = "7.2"
# Эти значения подтянутся из .env, если он настроен
TELEGRAM_TOKEN = os.getenv("TG_TOKEN", "YOUR_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TG_CHAT_ID", "YOUR_CHAT_ID")
CF_WORKER_URL = os.getenv("CF_WORKER", "")

# Порты для аудита
PORTS_TO_CHECK = {
    22: "SSH", 80: "HTTP", 443: "HTTPS",
    445: "SMB", 3389: "RDP", 8080: "WEB-Alt"
}

DEFAULT_THREADS = 60
LOG_FILE = "scan_history.log"
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
    """Парсер аргументов командной строки"""
    parser = argparse.ArgumentParser(description=f"Sentinel v{VERSION} - Network Intelligence Tool")
    parser.add_argument("-n", "--network", help="Target subnet (e.g. 192.168.1.0/24)", required=True)
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"Threads (default: {DEFAULT_THREADS})")
    parser.add_argument("-f", "--format", choices=['json', 'csv'], help="Save results to file (json/csv)")
    parser.add_argument("--silent", action="store_true", help="Don't send Telegram report")
    return parser.parse_args()

def get_ping_command(ip):
    """Определение ОС и выбор правильной команды ping"""
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    return ['ping', param, '1', '-W', '1', str(ip)]

def save_json(results, filename="scan_results.json"):
    """Экспорт в JSON с меткой времени (v7.2)"""
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
        print(f"[+] Results saved to {filename}")
    except Exception as e:
        print(f"[!] Error saving JSON: {e}")

def save_csv(results, filename="scan_results.csv"):
    """Экспорт в CSV с меткой времени (v7.2)"""
    if not results: return
    keys = ["ip", "name", "ports", "scan_time"]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore')
            writer.writeheader()
            for r in results:
                r["scan_time"] = timestamp
                writer.writerow(r)
        print(f"[+] Results saved to {filename}")
    except Exception as e:
        print(f"[!] Error saving CSV: {e}")

def send_telegram(message):
    """Отправка отчета с защитой от блокировок"""
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

def check_port(ip, port):
    """Проверка порта с обработкой исключений"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            return port if s.connect_ex((ip, port)) == 0 else None
    except:
        return None

def scan_host(ip):
    """Сканирование одного хоста"""
    ip_str = str(ip)
    try:
        p = subprocess.run(get_ping_command(ip_str),
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        if p.returncode == 0:
            try: name = socket.gethostbyaddr(ip_str)[0]
            except: name = "no-name"

            found = [f"{port}({label})" for port, label in PORTS_TO_CHECK.items() if check_port(ip_str, port)]
            p_info = ", ".join(found) if found else "no open ports"

            return {
                "ip": ip_str, "name": name, "ports": p_info,
                "tg": f"• `{ip_str.ljust(15)}` | *{name[:12]}* | {p_info}"
            }
    except: pass
    return None

def main():
    load_dotenv()  # Добавлено: загрузка переменных окружения из .env файла
    args = parse_arguments()

    os.system('cls' if platform.system().lower() == 'windows' else 'clear')
    print(BANNER)

    try:
        network = ipaddress.ip_network(args.network, strict=False)
    except Exception as e:
        print(f"❌ Network Error: {e}")
        return

    print(f"[*] Scanning {network.num_addresses} hosts using {platform.system()} engine...")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = [r for r in list(executor.map(scan_host, network.hosts())) if r]

    if results:
        print(f"\n{'IP ADDRESS'.ljust(17)} | {'HOSTNAME'.ljust(15)} | SERVICES")
        print("-" * 65)
        for r in results:
            print(f"{r['ip'].ljust(17)} | {r['name'][:15].ljust(15)} | {r['ports']}")

        if args.format == "json":
            save_json(results)
        elif args.format == "csv":
            save_csv(results)

        if not args.silent:
            header = f"📡 *Sentinel v{VERSION} Report*\nTarget: `{args.network}`\n\n"
            body = "\n".join([r['tg'] for r in results])
            send_telegram(header + body + f"\n\n✅ Found: *{len(results)}*")
            print("\n[+] Telegram report sent.")
    else:
        print("\n[-] No active hosts detected.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
