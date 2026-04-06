import argparse, subprocess, ipaddress, socket, requests, os, json, csv, sqlite3, platform, logging, re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

VERSION = "9.6"
DB_FILE = "sentinel_scans.db"
DEFAULT_THREADS = 100

TELEGRAM_TOKEN = os.getenv("TG_TOKEN", "YOUR_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TG_CHAT_ID", "YOUR_CHAT_ID")
CF_WORKER_URL = os.getenv("CF_WORKER", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK", "")

PORTS_TO_CHECK = {
    80: "HTTP", 8080: "HTTP-Alt", 8000: "HTTP-Dev", 8888: "HTTP-Dev2", 443: "HTTPS", 8443: "HTTPS-Alt",
    3000: "Node.js", 5000: "Flask", 5001: "Flask-Alt", 8001: "Dev-Server", 8002: "Dev-Server2",
    8003: "Dev-Server3", 4000: "Dev-Server4", 9000: "Dev-Server5", 9001: "Dev-Server6",
    7000: "Dev-Server7", 7001: "Dev-Server8", 6000: "Dev-Server9", 6001: "Dev-Server10", 11211: "Memcached",
    22: "SSH", 2222: "SSH-Alt1", 2223: "SSH-Alt2", 22000: "SSH-Alt3", 3389: "RDP", 5900: "VNC",
    5901: "VNC-Alt", 5800: "VNC-HTTP", 6000: "X11", 6001: "X11-Alt", 3386: "RDP-Alt", 3387: "RDP-Alt2",
    10000: "Webmin", 10001: "Webmin-Alt", 3306: "MySQL", 3307: "MySQL-Alt", 3308: "MySQL-Alt2",
    5432: "PostgreSQL", 5433: "PostgreSQL-Alt", 1433: "MSSQL", 1434: "MSSQL-Alt", 27017: "MongoDB",
    27018: "MongoDB-Alt", 27019: "MongoDB-Alt2", 6379: "Redis", 6380: "Redis-Alt", 5984: "CouchDB",
    5985: "CouchDB-Alt", 28017: "MongoDB-Web", 9042: "Cassandra", 7000: "Cassandra-Gossip",
    7001: "Cassandra-Gossip-Alt", 8086: "InfluxDB", 8087: "InfluxDB-Alt", 9200: "Elasticsearch",
    9201: "Elasticsearch-Alt", 9300: "Elasticsearch-Node", 12000: "Redis-Sentinel", 445: "SMB",
    139: "NetBIOS", 135: "RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 21: "FTP", 20: "FTP-DATA",
    990: "FTPS", 989: "FTPS-Alt", 69: "TFTP", 548: "AFP", 873: "Rsync", 2049: "NFS", 111: "Portmapper",
    2048: "Shoutcast", 25: "SMTP", 26: "SMTP-Alt", 587: "SMTP-TLS", 465: "SMTP-SSL", 110: "POP3",
    995: "POP3-SSL", 143: "IMAP", 993: "IMAP-SSL", 389: "LDAP", 636: "LDAP-SSL", 5269: "Jabber",
    5222: "Jabber-Client", 5223: "Jabber-SSL", 3689: "DAAP", 6969: "IRC", 6667: "IRC-Alt",
    6668: "IRC-Alt2", 6669: "IRC-Alt3", 6697: "IRC-SSL", 8161: "ActiveMQ", 8162: "ActiveMQ-Alt",
    6080: "Guacamole", 8090: "Confluence", 8091: "Confluence-Alt", 8889: "Jupyter-Alt", 4242: "OpenTSDB",
    4243: "OpenTSDB-Alt", 5601: "Kibana", 5602: "Kibana-Alt", 9990: "WildFly", 9991: "WildFly-Alt",
    161: "SNMP", 162: "SNMP-Trap", 199: "SMUX", 9090: "Prometheus", 9091: "Prometheus-Pushgateway",
    9100: "Node-Exporter", 8089: "Splunk", 8065: "Splunk-Input", 4949: "Munin", 2003: "Graphite-Carbon",
    2004: "Graphite-Carbon-Pickle", 2023: "Graphite-Whisper", 2024: "Graphite-Whisper-Alt", 8125: "StatsD",
    8126: "StatsD-Admin", 6831: "Jaeger-Agent", 6832: "Jaeger-Agent-Compact", 9411: "Zipkin",
    2375: "Docker", 2376: "Docker-TLS", 5001: "Registry-Alt", 10250: "Kubelet", 10255: "Kubelet-ReadOnly",
    10256: "Kube-Proxy", 4001: "Etcd", 2379: "Etcd-Server", 2380: "Etcd-Peer", 8500: "Consul",
    8501: "Consul-HTTPS", 8600: "Consul-DNS", 8601: "Consul-DNS-Alt", 8443: "Jenkins-HTTPS",
    9001: "SonarQube-Alt", 1194: "OpenVPN", 1195: "OpenVPN-Alt", 500: "IPSec-IKE", 4500: "IPSec-NAT",
    1723: "PPTP", 47: "GRE", 1701: "L2TP", 8008: "HTTP-Proxy", 3128: "Squid-Proxy", 8118: "Privoxy",
    9050: "Tor-SOCKS", 9051: "Tor-Control", 5986: "WinRM-TLS", 514: "Syslog", 515: "LPD", 631: "CUPS",
    50070: "Hadoop-NameNode", 50075: "Hadoop-DataNode", 50090: "Hadoop-Secondary", 8088: "Hadoop-ResourceMgr",
    9000: "Hadoop-JobTracker", 50060: "Hadoop-TaskTracker", 8020: "Hadoop-HDFS", 18080: "Spark-History",
    4040: "Spark-App-UI",
}

OS_SIGNATURES = {
    'Linux': {'patterns': [r'Ubuntu|Debian|CentOS|RHEL|Fedora|OpenSSH.*Linux|Linux Kernel'], 'ports': [22, 111, 2049], 'confidence': 85},
    'Windows': {'patterns': [r'Windows|Microsoft|WINNT|HOSTNAME|Kerberos|LDAP.*Microsoft|SMB.*Windows'], 'ports': [445, 139, 3389, 135, 5985], 'confidence': 90},
    'macOS': {'patterns': [r'macOS|Darwin|OSX|Apple|OpenSSH.*Darwin'], 'ports': [22, 548], 'confidence': 80},
    'FreeBSD': {'patterns': [r'FreeBSD|BSD|OpenSSH.*BSD'], 'ports': [22, 111], 'confidence': 75},
    'Router/Network Device': {'patterns': [r'Cisco|Ubiquiti|TP-Link|D-Link|Juniper|Fortinet|NETGEAR|MikroTik|SNMP|HTTP/1.0'], 'ports': [161, 162, 80, 8080, 23], 'confidence': 70},
    'Printer/IoT Device': {'patterns': [r'HP|Canon|Xerox|Brother|Printer|CUPS|IPP'], 'ports': [631, 515, 9100], 'confidence': 65},
    'Docker/Container': {'patterns': [r'Docker|Container|Kubernetes|X-Docker'], 'ports': [2375, 2376, 10250], 'confidence': 88},
}

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

🔍 BASIC SCAN (200 ports + OS FINGERPRINTING):
  python3 Sentinel.py -n 192.168.1.0/24

📊 EXPORT TO JSON:
  python3 Sentinel.py -n 192.168.1.0/24 -f json

📋 EXPORT TO CSV:
  python3 Sentinel.py -n 192.168.1.0/24 -f csv

⚡ INCREASE THREADS:
  python3 Sentinel.py -n 192.168.1.0/24 -t 200

🔕 NO NOTIFICATIONS:
  python3 Sentinel.py -n 192.168.1.0/24 --silent

📜 VIEW SCAN HISTORY:
  python3 Sentinel.py --history

📊 COMPARE SCANS:
  python3 Sentinel.py -n 192.168.1.0/24 --compare

═══════════════════════════════════════════════════════════════════════════════

✨ FEATURES:
  ✅ 200+ port scanning with version detection
  ✅ OS Fingerprinting (Linux, Windows, macOS, Router, Docker, IoT)
  ✅ Banner grabbing for service identification
  ✅ Telegram/Slack notifications
  ✅ SQLite scan history with comparison
  ✅ JSON/CSV export
  ✅ Cross-platform (Windows/Linux/Mac)

═══════════════════════════════════════════════════════════════════════════════
"""

class ScanDatabase:
    def __init__(self, db_file=DB_FILE):
        self.db_file = db_file
        self.init_db()

    def init_db(self):
        try:
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS scans
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, subnet TEXT, timestamp DATETIME, os_platform TEXT, total_found INTEGER)''')
            c.execute('''CREATE TABLE IF NOT EXISTS hosts
                         (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, ip TEXT, hostname TEXT, ports TEXT, os_guess TEXT, confidence INTEGER, FOREIGN KEY(scan_id) REFERENCES scans(id))''')
            conn.commit()
            conn.close()
        except Exception as e:
            logger.error(f"Database init error: {e}")

    def save_scan(self, subnet, results):
        try:
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            timestamp = datetime.now().isoformat()
            c.execute('''INSERT INTO scans (subnet, timestamp, os_platform, total_found) VALUES (?, ?, ?, ?)''',
                      (subnet, timestamp, platform.system(), len(results)))
            scan_id = c.lastrowid
            for r in results:
                c.execute('''INSERT INTO hosts (scan_id, ip, hostname, ports, os_guess, confidence) VALUES (?, ?, ?, ?, ?, ?)''',
                          (scan_id, r['ip'], r['name'], r['ports'], r.get('os_guess', 'Unknown'), r.get('os_confidence', 0)))
            conn.commit()
            conn.close()
            print(f"[+] Scan saved to database (ID: {scan_id})")
            return scan_id
        except Exception as e:
            logger.error(f"Error saving scan: {e}")

    def get_scan_history(self, limit=10):
        try:
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            c.execute('SELECT id, subnet, timestamp, total_found FROM scans ORDER BY id DESC LIMIT ?', (limit,))
            scans = c.fetchall()
            conn.close()
            return scans
        except Exception as e:
            logger.error(f"Error getting history: {e}")
            return []

    def compare_scans(self, subnet):
        try:
            conn = sqlite3.connect(self.db_file)
            c = conn.cursor()
            c.execute('SELECT id FROM scans WHERE subnet = ? ORDER BY id DESC LIMIT 2', (subnet,))
            scan_ids = [row[0] for row in c.fetchall()]
            if len(scan_ids) < 2:
                print("[-] Not enough scans to compare (need at least 2)")
                return None
            latest_id, previous_id = scan_ids[0], scan_ids[1]
            c.execute('SELECT ip, ports FROM hosts WHERE scan_id = ?', (latest_id,))
            latest = {row[0]: row[1] for row in c.fetchall()}
            c.execute('SELECT ip, ports FROM hosts WHERE scan_id = ?', (previous_id,))
            previous = {row[0]: row[1] for row in c.fetchall()}
            conn.close()
            return {'new': set(latest.keys()) - set(previous.keys()), 'gone': set(previous.keys()) - set(latest.keys()),
                    'changed': {ip for ip in set(latest.keys()) & set(previous.keys()) if latest[ip] != previous[ip]},
                    'latest': latest, 'previous': previous}
        except Exception as e:
            logger.error(f"Error comparing scans: {e}")

class OSFingerprinting:
    @staticmethod
    def guess_os(ip, ports_found, banners):
        scores = {}
        for os_name, sig in OS_SIGNATURES.items():
            score = 0
            matched_ports = [p for p in ports_found if p in sig['ports']]
            if matched_ports: score += len(matched_ports) * 20
            for banner_data in banners.values():
                if banner_data:
                    for pattern in sig['patterns']:
                        if re.search(pattern, str(banner_data), re.IGNORECASE):
                            score += 30
            if score > 0: scores[os_name] = (score, sig['confidence'])
        return (max(scores.items(), key=lambda x: x[1][0])[0], int(max(scores.items(), key=lambda x: x[1][0])[1][1] * (max(scores.items(), key=lambda x: x[1][0])[1][0] / 100))) if scores else ("Unknown", 0)

def parse_arguments():
    parser = argparse.ArgumentParser(description=f"Sentinel v{VERSION} - High-Speed Network Intelligence Tool",
                                     formatter_class=argparse.RawDescriptionHelpFormatter, epilog=HELP_EXAMPLES)
    parser.add_argument("-n", "--network", help="Target subnet (e.g., 192.168.1.0/24)", metavar="SUBNET")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help=f"Threads (default: {DEFAULT_THREADS})", metavar="NUM")
    parser.add_argument("-f", "--format", choices=['json', 'csv'], help="Export format (json/csv)", metavar="FORMAT")
    parser.add_argument("--silent", action="store_true", help="Disable notifications")
    parser.add_argument("--history", action="store_true", help="Show scan history")
    parser.add_argument("--compare", action="store_true", help="Compare with last scan")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {VERSION}")
    return parser.parse_args()

def send_notification(message, service='telegram'):
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

def check_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.3)
            return port if s.connect_ex((ip, port)) == 0 else None
    except: return None

def get_service_version(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((ip, port))
        if port in [80, 8080, 8000, 8888, 443, 8443, 8001, 8002, 8003, 4000, 9000, 9001, 7000, 7001, 6000, 6001]:
            try:
                s.send(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                banner = s.recv(1024).decode('utf-8', errors='ignore')
                for line in banner.split('\n'):
                    if 'Server:' in line:
                        s.close()
                        return line.replace('Server:', '').strip()[:40] or "unknown"
            except: pass
        try:
            banner = s.recv(1024).decode('utf-8', errors='ignore')
            s.close()
            return (banner.split('\n')[0].strip()[:40] if banner else "unknown")
        except:
            s.close()
        return "unknown"
    except socket.timeout: return "timeout"
    except ConnectionRefusedError: return "refused"
    except (socket.gaierror, socket.error, OSError) as e:
        logger.debug(f"Banner grab error for {ip}:{port} - {e}")
        return "error"

def scan_host(ip):
    ip_str = str(ip)
    try:
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        p = subprocess.run(['ping', param, '1', '-W', '1', ip_str], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode == 0:
            try: name = socket.gethostbyaddr(ip_str)[0]
            except: name = "no-name"
            found, ports_found, banners = [], [], {}
            for port, label in PORTS_TO_CHECK.items():
                if check_port(ip_str, port):
                    ports_found.append(port)
                    version = get_service_version(ip_str, port)
                    banners[port] = version
                    found.append(f"{port}({label}/{version})" if version and version not in ["unknown", "timeout", "refused", "error"] else f"{port}({label})")
            os_guess, os_confidence = OSFingerprinting.guess_os(ip_str, ports_found, banners)
            p_info = ", ".join(found) if found else "no open ports"
            return {"ip": ip_str, "name": name, "ports": p_info, "os_guess": os_guess, "os_confidence": os_confidence,
                    "tg": f"• `{ip_str.ljust(15)}` | *{name[:12]}* | {os_guess} ({os_confidence}%) | {p_info}"}
    except Exception as e:
        logger.warning(f"Host {ip_str} scan failed: {e}")
    return None

def show_history(db):
    print("\n[*] Scan History:\n" + "="*100)
    print(f"{'ID':<5} | {'Subnet':<20} | {'Time':<25} | {'Found':<10}\n" + "-"*100)
    scans = db.get_scan_history(limit=20)
    if not scans: print("[-] No scan history found")
    else:
        for scan_id, subnet, timestamp, total_found in scans:
            print(f"{scan_id:<5} | {subnet:<20} | {timestamp:<25} | {total_found:<10}")

def show_comparison(db, subnet):
    comparison = db.compare_scans(subnet)
    if not comparison: return
    print("\n[*] Scan Comparison Results:\n" + "="*100)
    if comparison['new']: print(f"\n✅ NEW HOSTS ({len(comparison['new'])}):\n   " + "\n   ".join(f"+ {ip}" for ip in sorted(comparison['new'])))
    if comparison['gone']: print(f"\n❌ GONE HOSTS ({len(comparison['gone'])}):\n   " + "\n   ".join(f"- {ip}" for ip in sorted(comparison['gone'])))
    if comparison['changed']: print(f"\n⚠️  CHANGED SERVICES ({len(comparison['changed'])}):\n" + "\n".join(f"   ~ {ip}\n     Was: {comparison['previous'][ip]}\n     Now: {comparison['latest'][ip]}" for ip in sorted(comparison['changed'])))

def main():
    load_dotenv()
    global TELEGRAM_TOKEN, TELEGRAM_CHAT_ID, CF_WORKER_URL, SLACK_WEBHOOK_URL
    TELEGRAM_TOKEN = os.getenv("TG_TOKEN", TELEGRAM_TOKEN)
    TELEGRAM_CHAT_ID = os.getenv("TG_CHAT_ID", TELEGRAM_CHAT_ID)
    CF_WORKER_URL = os.getenv("CF_WORKER", CF_WORKER_URL)
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK", SLACK_WEBHOOK_URL)

    args = parse_arguments()
    db = ScanDatabase()
    os.system('cls' if platform.system().lower() == 'windows' else 'clear')
    print(BANNER)

    if args.history: show_history(db); return
    if args.compare:
        if not args.network: print("[-] Error: --compare requires -n/--network"); return
        show_comparison(db, args.network); return
    if not args.network: print("[-] Error: -n/--network is required"); parser.print_help(); return

    try: network = ipaddress.ip_network(args.network, strict=False)
    except Exception as e: print(f"❌ Network Error: {e}"); return

    print(f"[*] Scanning {network.num_addresses} hosts with {len(PORTS_TO_CHECK)} ports...")
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        results = [r for r in list(executor.map(scan_host, network.hosts())) if r]

    if results:
        print(f"\n{'IP ADDRESS'.ljust(17)} | {'HOSTNAME'.ljust(15)} | {'OS'.ljust(20)} | SERVICES\n" + "-"*180)
        for r in results:
            os_info = f"{r['os_guess']} ({r['os_confidence']}%)"
            print(f"{r['ip'].ljust(17)} | {r['name'][:15].ljust(15)} | {os_info.ljust(20)} | {r['ports']}")

        db.save_scan(args.network, results)

        if args.format == "json":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_{timestamp}.json"
            try:
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump({"scan_metadata": {"version": VERSION, "timestamp": datetime.now().isoformat(),
                                                 "os_platform": platform.system(), "ports_scanned": len(PORTS_TO_CHECK),
                                                 "total_found": len(results)}, "hosts": results}, f, indent=4, ensure_ascii=False)
                print(f"\n[+] JSON exported to {filename}")
            except Exception as e:
                logger.error(f"Failed to save JSON: {e}")
        elif args.format == "csv":
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_{timestamp}.csv"
            try:
                with open(filename, "w", newline="", encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=["ip", "name", "os_guess", "os_confidence", "ports"])
                    writer.writeheader()
                    writer.writerows(results)
                print(f"\n[+] CSV exported to {filename}")
            except Exception as e:
                logger.error(f"Failed to save CSV: {e}")

        if not args.silent:
            report_header = f"📡 *Sentinel v{VERSION} Report*\nTarget: `{args.network}`\nPorts: {len(PORTS_TO_CHECK)}\n\n"
            report_body = "\n".join([r['tg'] for r in results])
            full_report = report_header + report_body + f"\n\n✅ Found: *{len(results)}*"
            if send_notification(full_report, 'telegram'): print("[+] Telegram report sent.")
            if SLACK_WEBHOOK_URL and send_notification(full_report, 'slack'): print("[+] Slack report sent.")
    else:
        print("\n[-] No active hosts detected.")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\n[!] Scan interrupted.")
