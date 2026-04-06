# Sentinel Ultimate v9.6

**Sentinel Ultimate** is a high-speed, professional network intelligence and security auditing tool. Version 9.6 introduces deep **OS Fingerprinting**, a persistent **SQLite Database** for scan history, and an automated **Scan Comparison** engine.

## Key Features
- **OS Fingerprinting (v9.6):** Intelligent detection of Windows, Linux, macOS, IoT, and Network devices based on TTL, port patterns, and banner analysis.
- **Elite Service Detection (200+ Ports):** Comprehensive coverage of Web, DBs, Cloud, DevOps, and Security services.
- **SQLite Persistence:** All scans are automatically saved to `sentinel_scans.db` for future auditing.
- **Diff Engine:** Compare current results with previous scans to identify new, gone, or modified hosts/services.
- **Deep Banner Grabbing:** Real-time version identification for SSH, HTTP (Server headers), and more.
- **Multi-Channel Reporting:** Automated delivery to Telegram (with Cloudflare bypass) and Slack.

# INSTALL requirements: pip install -r requirements.txt

# 1. Clone the repository
git clone https://github.com/agitd/sentinel-ultimate.git

# 2. Enter the project folder
cd sentinel-ultimate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure Environment
# Copy env.example to .env and fill in TG_TOKEN, TG_CHAT_ID, etc.

# 5. Run the scanner
python3 Sentinel.py -n 192.168.1.0/24

Usage (Аргументы запуска)

Sentinel Ultimate v9.6 supports advanced CLI commands for deep infrastructure auditing:

| Flag | Description | Example |
| :--- | :--- | :--- |
| `-n` | **Network** (Required CIDR) | `-n 192.168.1.0/24` |
| `-t` | **Threads** (Default: 100) | `-t 200` |
| `-f` | **Format** (json/csv) | `-f json` |
| `--history`| **View Database History** | `--history` |
| `--compare`| **Compare Scans** | `--compare -n 192.168.1.0/24` |
| `--silent` | **Disable Notifications** | `--silent` |
| `-h` | **Show Help Menu** | `-h` |

### Examples:

# Standard scan with OS detection and remote reporting
python3 Sentinel.py -n 192.168.1.0/24

# Fast scan and export results to CSV
python3 Sentinel.py -n 10.0.0.0/16 -t 250 -f csv

# Audit changes: See what changed since the last scan of this subnet
python3 Sentinel.py -n 192.168.1.0/24 --compare

# List all previous scan sessions from SQLite
python3 Sentinel.py --history

## OS Fingerprinting Support
* **Linux:** Ubuntu, Debian, CentOS, RHEL, Fedora
* **Windows:** Workstations, Servers, Active Directory nodes
* **Apple:** macOS (Darwin core)
* **Infrastructure:** Cisco, Ubiquiti, MikroTik, Fortinet
* **Containers:** Docker, Kubernetes nodes
* **IoT:** Printers (HP, Brother), CUPS, IPP devices
