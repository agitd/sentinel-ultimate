# Sentinel Ultimate v13.6.1
# Required: Install Ollama and run ollama pull llama3 before starting the scanner!!!!!!!

**Sentinel Ultimate** is a high-speed, professional network intelligence and security auditing tool. Version 13.6.1 introduces critical security auditing capabilities, legacy protocol detection, and automated vulnerability lookups.

## Key Features
- **AI Security Analyst:** Local neural network integration (Llama 3/Phi-3) for real-time security verdicts and automated threat assessment.
- **[NEW] AI Self-Learning Engine:** Automated dataset updates and model retraining via `--update-ai` to keep risk scores synchronized with global threat databases.
- **Start Scan** <img width="932" height="522" alt="start_scan" src="https://github.com/user-attachments/assets/e4772c1f-c561-4640-a316-11b0fee2bdba" />
- **AI Verdict** <img width="1897" height="486" alt="ai_scan_verdict" src="https://github.com/user-attachments/assets/007f7535-4ce0-4c17-9d61-beee347210a2" />
- **CVE Integration (v13.6):** Real-time vulnerability lookup for detected service versions via API (cve.circl.lu) with intelligent OS-based filtering.
- **SMBv1 Audit (v13.6):** Dedicated detection for the vulnerable SMBv1 protocol (EternalBlue vector), implemented with safe hex-payloads for Python 3.13.
- **SSH Auth Auditing (v13.6):** Automated checks for weak or default credentials on discovered SSH services.
- **OS Fingerprinting:** Intelligent detection of Windows, Linux, macOS, IoT, and containers based on port patterns and weighted banner analysis.
- **Elite Service Detection (200+ Ports):** Comprehensive coverage of web services, databases, DevOps stacks, and security systems.
- **Go-Powered Fuzzing:** Integrated high-speed directory fuzzer (Go-engine) running inside Docker for web service auditing.
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

# 5.1 Initialize AI Brain
Required for first run.
python3 main.py --update-ai

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
| `-m` | **Run Internal Tests** (pytest) | `-m` |
| `--update-ai`| **[NEW] Retrain AI Model** | `--update-ai` |
| `--fuzz`| **Run Go-Fuzzer on Web Ports** | `--fuzz` |
| `--history`| **View Database History** | `--history` |
| `--compare`| **Compare Scans** | `--compare -n 192.168.1.0/24` |
| `--silent` | **Disable Notifications** | `--silent` |
| `-h` | **Show Help Menu** | `-h` |

## Examples:

# Standard scan with AI verdict and console output
python3 main.py -n 192.168.1.0/24

# [NEW] Update AI dataset and retrain risk model
python3 main.py --update-ai

# Scan with AI analysis and export results to PDF
python3 main.py -n 192.168.1.0/24 -f pdf

# Scan with automated Web Fuzzing (Go-Engine)
python3 main.py -n 192.168.1.0/24 --fuzz

# Launch internal unit tests
export PYTHONPATH=$PYTHONPATH:.
python3 -m pytest tests/test_scanner.py -v

## Known Issues (v13.6)
* **Testing Suite:** Currently, 3 tests in `TestSecurityv136` may fail with a `RuntimeError` regarding the `event loop` in certain Kali Linux / Python 3.13 environments. This is a known compatibility issue with the `pytest-asyncio` runner and **does not affect the core scanner's functionality**. A fix is scheduled for v13.6.2.

## OS Fingerprinting Support
* **Linux:** Ubuntu, Debian, CentOS, RHEL, Fedora
* **Windows:** Workstations, Servers, Active Directory nodes
* **Apple:** macOS (Darwin core)
* **Infrastructure:** Cisco, Ubiquiti, MikroTik, Fortinet
* **Containers:** Docker, Kubernetes nodes
* **IoT:** Printers (HP, Brother), CUPS, IPP devices

## Disclaimer
This tool is developed for educational purposes and authorized security auditing only. The author is not responsible for any damage caused by misuse of this software. Always obtain permission before scanning any network.


