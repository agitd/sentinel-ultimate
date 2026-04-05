import argparse
import subprocess
import ipaddress
import socket
import requests
import os
import json
import csv
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ==================== [ CONFIGURATION ] ====================
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

BANNER = r"""
  _____            _   _             _
 / ____|          | | (_)           | |
| (___   ___ _ __ | |_ _ _ __   ___| |
 \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
 ____) |  __/ | | | |_| | | | |  __/ |
|_____/ \___|_| |_|\__|_|_| |_|\___|_|
      ULTIMATE NETWORK SCANNER v7.1
"""

def parse_arguments():
    """Обработка аргументов командной строки"""
    parser = argparse.ArgumentParser(description="Sentinel Ultimate - Network Intelligence Tool")
    parser.add_argument("-n", "--network", help="Target subnet (e.g. 192.168.1.0/24)", required=True)
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"Threads (default: {DEFAULT_THREADS})")
    parser.add_argument("-f", "--format", choices=['json', 'csv'], help="Save results to file (json/csv)")
    parser.add_argument("--silent", action="store_true", help="Don't send Telegram report")
    return parser.parse_args()

def save_json(results, filename="scan_results.json"):
    """Экспорт в JSON"""
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    print(f"[+] Results saved to {filename}")

def save_csv(results, filename="scan_results.csv"):
    """Экспорт в CSV"""
    if not results: return
    keys = ["ip", "name", "ports"]
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(results)
    print(f"[+] Results saved to {filename}")

def send_telegram(message):
    """Доставка отчета в Telegram"""
    endpoints = []
    if CF_WORKER_URL:
        endpoints.append(f"{CF_WORKER_URL.rstrip('/')}/bot{TELEGRAM_TOKEN}/sendMessage")

    endpoints.extend([
        f"https://api.telegram-proxy.org/bot{TELEGRAM_TOKEN}/sendMessage",
        f"https://tgproxy.it/bot{TELEGRAM_TOKEN}/sendMessage",
        f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    ])

    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}

    print("\n[*] Sending report to Telegram...")
    for url in endpoints:
        try:
            r = requests.post(url, json=payload, timeout=10)
            if r.status_code == 200:
                print(f"[+] Success via: {url.split('/')[2]}")
                return True
        except:
            continue
    print("[!] Telegram delivery failed.")
    return False

def check_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        return port if s.connect_ex((ip, port)) == 0 else None

def scan_host(ip):
    ip_str = str(ip)
    try:
        # Пинг хоста
        p = subprocess.run(['ping', '-c', '1', '-W', '1', ip_str],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode == 0:
            try: name = socket.gethostbyaddr(ip_str)[0]
            except: name = "no-name"

            # Проверка портов
            found = [f"{port}({label})" for port, label in PORTS_TO_CHECK.items() if check_port(ip_str, port)]
            p_info = ", ".join(found) if found else "no open ports"

            return {
                "ip": ip_str, "name": name, "ports": p_info,
                "tg": f"• `{ip_str.ljust(15)}` | *{name[:12]}* | {p_info}"
            }
    except: pass
    return None

def main():
    args = parse_arguments()

    os.system('clear' if os.name == 'posix' else 'cls')
    print(BANNER)

    try:
        network = ipaddress.ip_network(args.network, strict=False)
    except Exception as e:
        print(f"❌ Error: {e}")
        return

    start_time = datetime.now()
    print(f"[*] Analyzing {network.num_addresses} hosts with {args.threads} threads...")
    print(f"{'IP ADDRESS'.ljust(17)} | {'HOSTNAME'.ljust(15)} | SERVICES")
    print("-" * 65)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = [r for r in list(executor.map(scan_host, network.hosts())) if r]

    if results:
        # Логирование в текст
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"\n--- Scan: {start_time.strftime('%Y-%m-%d %H:%M')} ---\n")
            for r in results:
                line = f"{r['ip'].ljust(17)} | {r['name'][:15].ljust(15)} | {r['ports']}"
                print(line)
                f.write(line + "\n")

        # Экспорт в файл, если выбран формат
        if args.format == "json":
            save_json(results)
        elif args.format == "csv":
            save_csv(results)

        # Telegram отчет
        if not args.silent:
            header = f"📡 *Sentinel Report: {args.network}*\n\n"
            body = "\n".join([r['tg'] for r in results])
            footer = f"\n\n✅ Hosts found: *{len(results)}*"
            send_telegram(header + body + footer)

        print(f"\n[*] Done. Found: {len(results)}. Log: {LOG_FILE}")
    else:
        print("\n[-] No live hosts found.")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\n[!] Interrupted.")
