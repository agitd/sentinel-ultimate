# Sentinel Ultimate v13.5
# Required: Install Ollama and run ollama pull llama3 before starting the scanner!!!!!!!
**Sentinel Ultimate** is a high-speed, professional network intelligence and security auditing tool. Version 13.5 introduces a local AI-powered analysis engine (Ollama integration), an expanded signature database (200+ ports), and automated CVE vulnerability lookup.

## Key Features
- **AI Security Analyst (v13.5):** Local neural network integration (Llama 3/Phi-3) for real-time security verdicts and automated threat assessment.
- **OS Fingerprinting:** Intelligent detection of Windows, Linux, macOS, IoT, and containers based on port patterns and weighted banner analysis.
- **Elite Service Detection (200+ Ports):** Comprehensive coverage of web services, databases, DevOps stacks, and security systems.
- **Go-Powered Fuzzing:** Integrated high-speed directory fuzzer (Go-engine) running inside Docker for web service auditing.
- **CVE Integration:** Real-time vulnerability lookup for detected service versions via API.
- **SQLite Persistence:** All scan results are automatically saved to `sentinel_scans.db` for future auditing and historical logging.
- **Diff Engine:** Compare current results with previous scans to identify new, gone, or modified hosts and services.
- **Multi-Channel Reporting:** Support for PDF reports, JSON/CSV exports, and notifications via Telegram (with proxy support) or Slack.

## Installation

# 1. Clone the repository
git clone https://github.com/agitd/sentinel-ultimate.git

# 2. Enter the project folder
cd sentinel-ultimate

# 3. Install AI Engine (Ollama)
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3

# 4. Install System Dependencies (Required for Scapy)
sudo apt update && sudo apt install libpcap-dev

# 5. Install Python dependencies
pip install -r requirements.txt
sudo pip3 install fpdf2

# 6. Build Go-Fuzzer Engine (Docker)
cd fuzzer-engine
docker build -t sentinel-fuzzer .
cd ..

# 7. Configure Environment
# Rename .env.example to .env and fill in your API tokens and AI settings:
mv .env.example .env
nano .env  # Ensure AI_ENABLED=True and AI_MODEL=llama3 are set

# 8. Run the scanner
python3 main.py -n 192.168.1.0/24

## Usage (Launch Arguments)

| Flag | Description | Example |
| :--- | :--- | :--- |
| `-n` | **Network** (CIDR notation) | `-n 192.168.1.0/24` |
| `-t` | **Threads** (Default: 200) | `-t 500` |
| `-f` | **Format** (pdf/json/csv export) | `-f pdf` |
| `-m` | **Run Internal Tests** (pytest) | `-m pytest -v` |
| `--fuzz`| **Run Go-Fuzzer on Web Ports** | `--fuzz` |
| `--history`| **View Database History** | `--history` |
| `--compare`| **Compare Scans** | `--compare -n 192.168.1.0/24` |
| `--silent` | **Disable Notifications** | `--silent` |
| `-h` | **Show Help Menu** | `-h` |

## Examples:

# Standard scan with AI verdict and console output
python3 main.py -n 192.168.1.0/24

# Scan with AI analysis and export results to PDF
python3 main.py -n 192.168.1.0/24 -f pdf

# Scan with automated Web Fuzzing (Go-Engine)
python3 main.py -n 192.168.1.0/24 --fuzz

# Audit changes: See what changed since the last scan of this subnet
python3 main.py -n 192.168.1.0/24 --compare

# List all previous scan sessions from SQLite
python3 main.py --history

# Launch internal unit tests
python3 main.py -m

# Advanced: Target scan with increased timeout for slow AI responses
python3 main.py -n 188.254.86.158

## OS Fingerprinting Support
* **Linux:** Ubuntu, Debian, CentOS, RHEL, Fedora
* **Windows:** Workstations, Servers, Active Directory nodes
* **Apple:** macOS (Darwin core)
* **Infrastructure:** Cisco, Ubiquiti, MikroTik, Fortinet
* **Containers:** Docker, Kubernetes nodes
* **IoT:** Printers (HP, Brother), CUPS, IPP devices

## Disclaimer
This tool is developed for educational purposes and authorized security auditing only. The author is not responsible for any damage caused by misuse of this software. Always obtain permission before scanning any network.
