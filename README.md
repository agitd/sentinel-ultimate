# Sentinel Ultimate v11.0

**Sentinel Ultimate** is a high-speed, professional network intelligence and security auditing tool. Version 11.0 introduces a fully asynchronous scanning engine, an expanded signature database (200+ ports), and automated CVE vulnerability lookup.

## Key Features
- **OS Fingerprinting (v11.0):** Intelligent detection of Windows, Linux, macOS, IoT, and containers based on port patterns and weighted banner analysis.
- **Elite Service Detection (200+ Ports):** Comprehensive coverage of web services, databases, DevOps stacks, and security systems.
- **CVE Integration:** Real-time vulnerability lookup for detected service versions via API.
- **SQLite Persistence:** All scan results are automatically saved to `sentinel_scans.db` for future auditing and historical logging.
- **Diff Engine:** Compare current results with previous scans to identify new, gone, or modified hosts and services.
- **Multi-Channel Reporting:** Support for PDF reports, JSON/CSV exports, and notifications via Telegram (with proxy support) or Slack.

## Installation

# 1. Clone the repository
git clone https://github.com/youruser/sentinel-ultimate.git

# 2. Enter the project folder
cd sentinel-ultimate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure Environment
# Rename .env.example to .env and fill in your API tokens:
mv env.example .env
nano .env  # Fill in TG_TOKEN, TG_CHAT_ID, etc.

# 5. Run the scanner
python3 main.py -n 192.168.1.0/24

## Usage (Launch Arguments)

| Flag | Description | Example |
| :--- | :--- | :--- |
| `-n` | **Network** (CIDR notation) | `-n 192.168.1.0/24` |
| `-t` | **Threads** (Default: 200) | `-t 500` |
| `-f` | **Format** (pdf/json/csv export) | `-f pdf` |
| `-m` | **Run Internal Tests** (pytest) | `-m pytest -v` |
| `--history`| **View Database History** | `--history` |
| `--compare`| **Compare Scans** | `--compare -n 192.168.1.0/24` |
| `--silent` | **Disable Notifications** | `--silent` |
| `-h` | **Show Help Menu** | `-h` |

## Examples:

# Standard scan with OS detection and reporting
python3 main.py -n 192.168.1.0/24

# Scan and export results to PDF
python3 main.py -n 10.0.0.0/16 -f pdf

# Audit changes: See what changed since the last scan of this subnet
python3 main.py -n 192.168.1.0/24 --compare

# List all previous scan sessions from SQLite
python3 main.py --history

# Launch internal unit tests
python3 main.py -m

## OS Fingerprinting Support
* **Linux:** Ubuntu, Debian, CentOS, RHEL, Fedora
* **Windows:** Workstations, Servers, Active Directory nodes
* **Apple:** macOS (Darwin core)
* **Infrastructure:** Cisco, Ubiquiti, MikroTik, Fortinet
* **Containers:** Docker, Kubernetes nodes
* **IoT:** Printers (HP, Brother), CUPS, IPP devices
