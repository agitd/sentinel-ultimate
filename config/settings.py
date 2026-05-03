import os
from typing import Dict, Any

VERSION = "13.6"
DB_FILE = "sentinel_scans.db"
DEFAULT_THREADS = 100

# Настройки уведомлений
TELEGRAM_TOKEN = os.getenv("TG_TOKEN", "YOUR_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TG_CHAT_ID", "YOUR_CHAT_ID")
CF_WORKER_URL = os.getenv("CF_WORKER", "")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK", "")

# --- AI ANALYZER SETTINGS (Локальный анализ через Ollama) ---
AI_ENABLED = os.getenv("AI_ENABLED", "True").lower() == "true"
AI_PROVIDER = "ollama"
AI_API_URL = "http://localhost:11434/api/generate"
AI_MODEL = "llama3"
# ----------------------------------------------------------

PORTS_TO_CHECK: Dict[int, str] = {
    80: "HTTP", 8080: "HTTP-Alt", 8000: "HTTP-Dev", 8888: "HTTP-Dev2", 443: "HTTPS", 8443: "HTTPS-Alt",
    3000: "Node.js", 5000: "Flask", 5001: "Flask-Alt", 8001: "Dev-Server", 8002: "Dev-Server2",
    8003: "Dev-Server3", 4000: "Dev-Server4", 9000: "Dev-Server5", 9001: "Dev-Server6",
    7000: "Dev-Server7", 7001: "Dev-Server8", 6000: "Dev-Server9", 6001: "Dev-Server10", 11211: "Memcached",
    22: "SSH", 2222: "SSH-Alt1", 2223: "SSH-Alt2", 22000: "SSH-Alt3", 3389: "RDP", 5900: "VNC",
    5901: "VNC-Alt", 5800: "VNC-HTTP", 6000: "X11", 6001: "X11-Alt", 3386: "RDP-Alt", 3387: "RDP-Alt2",
    10000: "Webmin", 10001: "Webmin-Alt", 3306: "MySQL", 3307: "MySQL-Alt", 3308: "MySQL-Alt2",
    5432: "PostgreSQL", 5433: "PostgreSQL-Alt", 1433: "MSSQL", 1434: "MSSQL-Alt", 27017: "MongoDB",
    27018: "MongoDB-Alt", 27019: "MongoDB-Alt2", 6379: "Redis", 6380: "Redis-Alt", 5984: "CouchDB",
    5985: "CouchDB-Alt", 28017: "MongoDB-Web", 9042: "Cassandra", 8086: "InfluxDB", 8087: "InfluxDB-Alt",
    9200: "Elasticsearch", 9201: "Elasticsearch-Alt", 9300: "Elasticsearch-Node", 12000: "Redis-Sentinel",
    445: "SMB", 139: "NetBIOS", 135: "RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 21: "FTP", 20: "FTP-DATA",
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
    2375: "Docker", 2376: "Docker-TLS", 10250: "Kubelet", 10255: "Kubelet-ReadOnly",
    10256: "Kube-Proxy", 4001: "Etcd", 2379: "Etcd-Server", 2380: "Etcd-Peer", 8500: "Consul",
    8501: "Consul-HTTPS", 8600: "Consul-DNS", 8601: "Consul-DNS-Alt", 9001: "SonarQube-Alt", 1194: "OpenVPN",
    1195: "OpenVPN-Alt", 500: "IPSec-IKE", 4500: "IPSec-NAT", 1723: "PPTP", 47: "GRE", 1701: "L2TP",
    8008: "HTTP-Proxy", 3128: "Squid-Proxy", 8118: "Privoxy", 9050: "Tor-SOCKS", 9051: "Tor-Control",
    5986: "WinRM-TLS", 514: "Syslog", 515: "LPD", 631: "CUPS", 50070: "Hadoop-NameNode",
    50075: "Hadoop-DataNode", 50090: "Hadoop-Secondary", 8088: "Hadoop-ResourceMgr",
    18080: "Spark-History", 4040: "Spark-App-UI", 23: "Telnet", 79: "Finger", 119: "NNTP",
    444: "SNPP", 513: "Rlogin", 88: "Kerberos", 102: "MS-Exchange", 113: "Ident", 179: "BGP",
    464: "Kpasswd", 543: "Klogin", 544: "Kshell", 554: "RTSP", 646: "LDP", 1720: "H.323",
    1883: "MQTT", 2483: "Oracle-TNS", 2484: "Oracle-TNS-SSL", 3074: "Xbox-Live",
    3268: "Global-Catalog", 3269: "Global-Catalog-SSL", 3724: "WoW", 4840: "OPC-UA",
    5060: "SIP", 5061: "SIP-TLS", 5353: "mDNS", 5672: "RabbitMQ", 5938: "TeamViewer",
    8243: "WSO2-HTTPS", 8333: "Bitcoin", 9092: "Kafka", 9999: "UrBackup", 25565: "Minecraft",
    27015: "Source-Engine", 31337: "Back-Orifice", 49152: "Supermicro-IPMI",
    65432: "Brute-Force-Target", 1900: "SSDP", 53: "DNS", 123: "NTP", 194: "IRC-Chat",
    1521: "Oracle-DB", 2082: "cPanel", 2083: "cPanel-SSL", 2086: "WHM", 2087: "WHM-SSL",
    5666: "Nagios-NRPE", 6443: "Kubernetes-API", 7077: "Spark-Master", 8081: "Artifactory",
    9091: "Transmission", 32400: "Plex", 1812: "RADIUS", 1813: "RADIUS-Acct", 2379: "Etcd-Client",
    2380: "Etcd-Peer-Srv", 3478: "STUN", 3690: "SVN", 4369: "Erlang-EPMD", 5003: "FileMaker",
    5228: "GCM", 5432: "Postgres-Srv", 5671: "RabbitMQ-SSL", 5900: "VNC-Srv", 5984: "CouchDB-Srv",
    6379: "Redis-Srv", 6667: "IRC-Srv", 8000: "Internet-Radio-Srv", 8080: "Tomcat", 8883: "MQTT-SSL",
    9000: "Sonar-Srv", 9042: "Cassandra-Srv", 9100: "Printer-Srv", 10000: "Webmin-Srv", 27017: "Mongo-DB",
    28017: "Mongo-Web-Srv", 50000: "SAP-Srv"
}

OS_SIGNATURES: Dict[str, Dict[str, Any]] = {
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
  python3 main.py -n 192.168.1.0/24

📊 EXPORT TO JSON:
  python3 main.py -n 192.168.1.0/24 -f json

📋 EXPORT TO CSV:
  python3 main.py -n 192.168.1.0/24 -f csv

⚡ INCREASE THREADS:
  python3 main.py -n 192.168.1.0/24 -t 200

🔕 NO NOTIFICATIONS:
  python3 main.py -n 192.168.1.0/24 --silent

📜 VIEW SCAN HISTORY:
  python3 main.py --history

📊 COMPARE SCANS:
  python3 main.py -n 192.168.1.0/24 --compare

🧪 RUN TESTS:
  python3 -m pytest tests/ -v

🚀 WEB FUZZING (GO-ENGINE):
  python3 main.py -n 192.168.1.0/24 --fuzz

⚡ FUZZING WITH CUSTOM WORDLIST:
  python3 main.py -n 192.168.1.0/24 --fuzz -t 50
"""
