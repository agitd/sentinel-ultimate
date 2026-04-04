import subprocess
import ipaddress
import socket
import requests
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# ==================== [ CONFIGURATION ] ====================
# Рекомендуется использовать переменные окружения (env)
# Впишите свои данные ниже или задайте их в системе
TELEGRAM_TOKEN = os.getenv("TG_TOKEN", "YOUR_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TG_CHAT_ID", "YOUR_CHAT_ID")
CF_WORKER_URL = os.getenv("CF_WORKER", "") 

PORTS_TO_CHECK = {
    22: "SSH", 80: "HTTP", 443: "HTTPS", 
    445: "SMB", 3389: "RDP", 8080: "WEB-Alt"
}

THREADS = 60
LOG_FILE = "scan_history.log"
# ==========================================================

BANNER = r"""
  _____            _   _             _ 
 / ____|          | | (_)           | |
| (___   ___ _ __ | |_ _ _ __   ___| |
 \___ \ / _ \ '_ \| __| | '_ \ / _ \ |
 ____) |  __/ | | | |_| | | | |  __/ |
|_____/ \___|_| |_|\__|_|_| |_|\___|_|
      ULTIMATE NETWORK SCANNER v7.0
"""

def send_telegram(message):
    """Multi-stage delivery to bypass blocks"""
    endpoints = []
    if CF_WORKER_URL:
        endpoints.append(f"{CF_WORKER_URL.rstrip('/')}/bot{TELEGRAM_TOKEN}/sendMessage")
    
    endpoints.extend([
        f"https://api.telegram-proxy.org/bot{TELEGRAM_TOKEN}/sendMessage",
        f"https://tgproxy.it/bot{TELEGRAM_TOKEN}/sendMessage",
        f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    ])

    payload = {"chat_id": TELEGRAM_CHAT_ID, "text": message, "parse_mode": "Markdown"}

    print("\n[*] Piercing Telegram blocks...")
    for url in endpoints:
        try:
            r = requests.post(url, json=payload, timeout=12)
            if r.status_code == 200:
                print(f"[+] Success via: {url.split('/')[2]}")
                return True
        except:
            continue
    print("[!] Connection failed. Check your network or use Cloudflare Worker.")
    return False

def check_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.4)
        return port if s.connect_ex((ip, port)) == 0 else None

def scan_host(ip):
    ip_str = str(ip)
    try:
        p = subprocess.run(['ping', '-c', '1', '-W', '1', ip_str], 
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
    os.system('clear' if os.name == 'posix' else 'cls')
    print(BANNER)
    
    net_input = input("Enter subnet (e.g., 192.168.1.0/24): ").strip()
    try:
        network = ipaddress.ip_network(net_input, strict=False)
    except:
        print("❌ Error: Invalid subnet format.")
        return

    start_time = datetime.now()
    print(f"[*] Analyzing {network.num_addresses} hosts...")
    print(f"{'IP ADDRESS'.ljust(17)} | {'HOSTNAME'.ljust(15)} | SERVICES")
    print("-" * 65)

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        results = [r for r in list(executor.map(scan_host, network.hosts())) if r]

    if results:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"\n--- Scan: {start_time.strftime('%Y-%m-%d %H:%M')} ---\n")
            for r in results:
                line = f"{r['ip'].ljust(17)} | {r['name'][:15].ljust(15)} | {r['ports']}"
                print(line)
                f.write(line + "\n")

        header = f"📡 *Sentinel Report: {net_input}*\n\n"
        body = "\n".join([r['tg'] for r in results])
        footer = f"\n\n✅ Hosts found: *{len(results)}*"
        send_telegram(header + body + footer)
        print(f"\n[*] Done. Found: {len(results)}. Log: {LOG_FILE}")
    else:
        print("\n[-] No live hosts found.")s

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\n[!] Interrupted by user.")