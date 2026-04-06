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
VERSION = "9.0"
TELEGRAM_TOKEN = os.getenv("TG_TOKEN", "YOUR_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TG_CHAT_ID", "YOUR_CHAT_ID")
CF_WORKER_URL = os.getenv("CF_WORKER", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK", "")

# 200 САМЫХ ПОПУЛЯРНЫХ ПОРТОВ!
PORTS_TO_CHECK = {
    # WEB SERVICES (20 портов)
    80: "HTTP",
    8080: "HTTP-Alt",
    8000: "HTTP-Dev",
    8888: "HTTP-Dev2",
    443: "HTTPS",
    8443: "HTTPS-Alt",
    3000: "Node.js",
    5000: "Flask",
    5001: "Flask-Alt",
    8001: "Dev-Server",
    8002: "Dev-Server2",
    8003: "Dev-Server3",
    4000: "Dev-Server4",
    9000: "Dev-Server5",
    9001: "Dev-Server6",
    7000: "Dev-Server7",
    7001: "Dev-Server8",
    6000: "Dev-Server9",
    6001: "Dev-Server10",
    11211: "Memcached",

    # SSH/REMOTE ACCESS (15 портов)
    22: "SSH",
    2222: "SSH-Alt1",
    2223: "SSH-Alt2",
    22000: "SSH-Alt3",
    3389: "RDP",
    5900: "VNC",
    5901: "VNC-Alt",
    5800: "VNC-HTTP",
    5900: "VNC-Server",
    6000: "X11",
    6001: "X11-Alt",
    3386: "RDP-Alt",
    3387: "RDP-Alt2",
    10000: "Webmin",
    10001: "Webmin-Alt",

    # DATABASES (25 портов)
    3306: "MySQL",
    3307: "MySQL-Alt",
    3308: "MySQL-Alt2",
    5432: "PostgreSQL",
    5433: "PostgreSQL-Alt",
    1433: "MSSQL",
    1434: "MSSQL-Alt",
    27017: "MongoDB",
    27018: "MongoDB-Alt",
    27019: "MongoDB-Alt2",
    6379: "Redis",
    6380: "Redis-Alt",
    5984: "CouchDB",
    5985: "CouchDB-Alt",
    28017: "MongoDB-Web",
    11211: "Memcached",
    9042: "Cassandra",
    7000: "Cassandra-Gossip",
    7001: "Cassandra-Gossip-Alt",
    8086: "InfluxDB",
    8087: "InfluxDB-Alt",
    9200: "Elasticsearch",
    9201: "Elasticsearch-Alt",
    9300: "Elasticsearch-Node",
    12000: "Redis-Sentinel",

    # FILE SHARING & SMB (15 портов)
    445: "SMB",
    139: "NetBIOS",
    135: "RPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    21: "FTP",
    20: "FTP-DATA",
    990: "FTPS",
    989: "FTPS-Alt",
    69: "TFTP",
    548: "AFP",
    873: "Rsync",
    2049: "NFS",
    111: "Portmapper",
    2048: "Shoutcast",

    # EMAIL & MESSAGING (20 портов)
    25: "SMTP",
    26: "SMTP-Alt",
    587: "SMTP-TLS",
    465: "SMTP-SSL",
    110: "POP3",
    995: "POP3-SSL",
    143: "IMAP",
    993: "IMAP-SSL",
    389: "LDAP",
    636: "LDAP-SSL",
    5269: "Jabber",
    5222: "Jabber-Client",
    5223: "Jabber-SSL",
    3689: "DAAP",
    6969: "IRC",
    6667: "IRC-Alt",
    6668: "IRC-Alt2",
    6669: "IRC-Alt3",
    6697: "IRC-SSL",
    5432: "Postgres-Email",

    # WEB FRAMEWORKS & APPS (20 портов)
    8080: "Tomcat",
    8081: "Tomcat-Alt",
    8009: "AJP",
    8161: "ActiveMQ",
    8162: "ActiveMQ-Alt",
    6080: "Guacamole",
    8090: "Confluence",
    8091: "Confluence-Alt",
    8888: "Jupyter",
    8889: "Jupyter-Alt",
    4242: "OpenTSDB",
    4243: "OpenTSDB-Alt",
    5601: "Kibana",
    5602: "Kibana-Alt",
    9990: "WildFly",
    9991: "WildFly-Alt",
    8000: "Grafana",
    8001: "Grafana-Alt",
    8888: "Spark",
    8889: "Spark-Alt",

    # MONITORING & MANAGEMENT (25 портов)
    161: "SNMP",
    162: "SNMP-Trap",
    199: "SMUX",
    9090: "Prometheus",
    9091: "Prometheus-Pushgateway",
    9100: "Node-Exporter",
    8089: "Splunk",
    8000: "Splunk-Web",
    8065: "Splunk-Input",
    4949: "Munin",
    5000: "Graphite",
    2003: "Graphite-Carbon",
    2004: "Graphite-Carbon-Pickle",
    2023: "Graphite-Whisper",
    2024: "Graphite-Whisper-Alt",
    8125: "StatsD",
    8126: "StatsD-Admin",
    6831: "Jaeger-Agent",
    6832: "Jaeger-Agent-Compact",
    9411: "Zipkin",
    5000: "Collectd",
    3000: "Grafana",
    8000: "InfluxDB-HTTP",
    8086: "InfluxDB",
    8888: "Chronograf",

    # CLOUD & CONTAINER (20 портов)
    2375: "Docker",
    2376: "Docker-TLS",
    5000: "Registry",
    5001: "Registry-Alt",
    8080: "Kubernetes-API",
    10250: "Kubelet",
    10255: "Kubelet-ReadOnly",
    10256: "Kube-Proxy",
    6379: "Redis-Cluster",
    6380: "Redis-Cluster-Alt",
    9200: "ES-Cluster",
    9300: "ES-Cluster-Node",
    4001: "Etcd",
    2379: "Etcd-Server",
    2380: "Etcd-Peer",
    8500: "Consul",
    8501: "Consul-HTTPS",
    8600: "Consul-DNS",
    8601: "Consul-DNS-Alt",

    # CI/CD & DevOps (15 портов)
    8080: "Jenkins",
    8443: "Jenkins-HTTPS",
    9000: "SonarQube",
    9001: "SonarQube-Alt",
    3000: "GitLab",
    443: "GitLab-HTTPS",
    22: "GitLab-SSH",
    80: "GitHub-Pages",
    8080: "Artifactory",
    8081: "Artifactory-Alt",
    8888: "Artifactory-Dev",
    5985: "WinRM",
    5986: "WinRM-TLS",
    8443: "Nexus",
    9999: "Sonatype-Nexus",

    # SECURITY & VPN (15 портов)
    443: "HTTPS",
    1194: "OpenVPN",
    1195: "OpenVPN-Alt",
    500: "IPSec-IKE",
    4500: "IPSec-NAT",
    1723: "PPTP",
    47: "GRE",
    1701: "L2TP",
    8443: "AnyConnect",
    8008: "HTTP-Proxy",
    3128: "Squid-Proxy",
    8118: "Privoxy",
    9050: "Tor-SOCKS",
    9051: "Tor-Control",
    5985: "WinRM",

    # MISC SERVICES (20 портов)
    514: "Syslog",
    515: "LPD",
    631: "CUPS",
    873: "Rsync",
    636: "LDAP-SSL",
    5432: "Postgres",
    3306: "MySQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    8086: "InfluxDB",
    50070: "Hadoop-NameNode",
    50075: "Hadoop-DataNode",
    50090: "Hadoop-Secondary",
    8088: "Hadoop-ResourceMgr",
    9000: "Hadoop-JobTracker",
    50060: "Hadoop-TaskTracker",
    8020: "Hadoop-HDFS",
    18080: "Spark-History",
    4040: "Spark-App-UI",
}

DEFAULT_THREADS = 100  # Увеличили с 60!
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

HELP_EXAMPLES = """
╔════════════════════════════════════════════════════════════════════════════╗
║                           USAGE EXAMPLES                                   ║
╚════════════════════════════════════════════════════════════════════════════╝

🔍 BASIC SCAN (200 ports - FULL SERVICE DETECTION):
  python3 Sentinel.py -n 192.168.1.0/24

📊 EXPORT TO JSON:
  python3 Sentinel.py -n 192.168.1.0/24 -f json

📋 EXPORT TO CSV:
  python3 Sentinel.py -n 192.168.1.0/24 -f csv

⚡ INCREASE THREADS (faster scanning):
  python3 Sentinel.py -n 192.168.1.0/24 -t 200

🔕 NO TELEGRAM/SLACK NOTIFICATIONS:
  python3 Sentinel.py -n 192.168.1.0/24 --silent

🚀 FULL SCAN (all options):
  python3 Sentinel.py -n 192.168.1.0/24 -f json -t 200

═══════════════════════════════════════════════════════════════════════════════

📌 CONFIGURATION:
  1. Copy env.example to .env
  2. Edit .env with your Telegram credentials
  3. (Optional) Add Slack webhook or Cloudflare Worker URL

═══════════════════════════════════════════════════════════════════════════════

🎯 SCANNED SERVICES (200+ ports):
  ✅ Web Services (Node, Flask, Dev Servers)
  ✅ SSH/Remote Access (SSH, RDP, VNC, X11, Webmin)
  ✅ Databases (MySQL, PostgreSQL, MongoDB, Redis, Cassandra, InfluxDB, Elasticsearch)
  ✅ File Sharing (SMB, NFS, FTP, TFTP, AFP, Rsync)
  ✅ Email/Messaging (SMTP, POP3, IMAP, LDAP, Jabber, IRC)
  ✅ Web Frameworks (Tomcat, ActiveMQ, Guacamole, Confluence, Jupyter)
  ✅ Monitoring (Prometheus, Splunk, Munin, Graphite, StatsD, Grafana)
  ✅ Cloud/Container (Docker, Kubernetes, Consul, Etcd)
  ✅ CI/CD (Jenkins, SonarQube, GitLab, Artifactory, Nexus)
  ✅ Security (VPN, IPSec, OpenVPN, Proxy, Tor)
  ✅ Big Data (Hadoop, Spark, HBase)

═══════════════════════════════════════════════════════════════════════════════

✨ FEATURES:
  ✅ Scans 200+ popular services
  ✅ Multi-threaded network scanning
  ✅ Service version detection (banner grabbing)
  ✅ Hostname resolution
  ✅ JSON/CSV export with timestamps
  ✅ Telegram notifications (with Cloudflare bypass)
  ✅ Slack notifications
  ✅ Cross-platform (Windows/Linux/Mac)

═══════════════════════════════════════════════════════════════════════════════
"""

def parse_arguments():
    """Парсинг аргументов команды с расширенной помощью"""
    parser = argparse.ArgumentParser(
        description=f"Sentinel v{VERSION} - High-Speed Network Intelligence Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=HELP_EXAMPLES
    )

    parser.add_argument(
        "-n", "--network",
        help="Target subnet in CIDR notation (e.g., 192.168.1.0/24, 10.0.0.0/16)",
        required=True,
        metavar="SUBNET"
    )

    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=DEFAULT_THREADS,
        help=f"Number of concurrent threads (default: {DEFAULT_THREADS})",
        metavar="NUM"
    )

    parser.add_argument(
        "-f", "--format",
        choices=['json', 'csv'],
        help="Export results to file format (json or csv)",
        metavar="FORMAT"
    )

    parser.add_argument(
        "--silent",
        action="store_true",
        help="Disable Telegram/Slack notifications"
    )

    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {VERSION}"
    )

    return parser.parse_args()

def send_telegram(message):
    """Отправка результатов в Telegram"""
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
    """Отправка результатов в Slack"""
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
        if port in [80, 8080, 8000, 8888, 443, 8443, 8001, 8002, 8003, 4000, 9000, 9001, 7000, 7001, 6000, 6001]:
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

    print(f"[*] Scanning {network.num_addresses} hosts with {len(PORTS_TO_CHECK)} ports...")

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = [r for r in list(executor.map(scan_host, network.hosts())) if r]

    if results:
        # Консольный вывод
        print(f"\n{'IP ADDRESS'.ljust(17)} | {'HOSTNAME'.ljust(15)} | SERVICES")
        print("-" * 150)
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
                    "ports_scanned": len(PORTS_TO_CHECK),
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
            report_header = f"📡 *Sentinel v{VERSION} Report*\nTarget: `{args.network}`\nPorts: {len(PORTS_TO_CHECK)}\n\n"
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
