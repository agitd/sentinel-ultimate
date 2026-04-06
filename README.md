# Sentinel Ultimate v8.5

**Sentinel Ultimate** is a high-speed network intelligence tool designed for Kali Linux and security enthusiasts. It efficiently scans subnets, identifies active hosts, resolves hostnames, and now performs deep service version detection (Banner Grabbing).

## Key Features
- **Multi-threaded Engine:** Powered by `ThreadPoolExecutor` for rapid network discovery.
- **Service Versioning (v8.5):** Advanced banner grabbing for SSH, HTTP, SMB, and more to identify service versions.
- **Cross-Platform Core:** Intelligent OS detection for both Windows and Unix-based systems.
- **Dual-Channel Reporting:** Integrated Telegram (via Proxy/Workers) and Slack webhook support.
- **Robust Error Handling:** Specific socket and OS exception tracking for maximum stability.
- **Advanced Export:** Auto-timestamped reports in JSON or CSV formats.

# INSTALL requirements: pip install requests python-dotenv

# 1. Clone the repository
git clone https://github.com/agitd/sentinel-ultimate.git

# 2. Enter the project folder
cd sentinel-ultimate

# 3. Install the required libraries
pip install requests python-dotenv

# 4. Run the scanner
# Note: Ensure your .env file (TG_TOKEN, TG_CHAT_ID, SLACK_WEBHOOK) is configured
python3 Sentinel.py -n 192.168.1.0/24

Usage 

Sentinel Ultimate supports CLI arguments for automation and deep scanning:

| Flag | Description | Example |
| :--- | :--- | :--- |
| `-n` | **Network** (Required) | `-n 192.168.1.0/24` |
| `-t` | **Threads** (Default: 60) | `-t 100` |
| `-f` | **Format** (json/csv) | `-f json` |
| `--silent` | **No Remote Reports** | `--silent` |

### Examples:

# Basic scan with version detection and Slack/TG reports
python3 Sentinel.py -n 192.168.1.0/24

# Save detailed service versions to JSON
python3 Sentinel.py -n 192.168.1.0/24 -f json

# Fast silent scan (no notifications)
python3 Sentinel.py -n 10.0.0.0/24 -t 150 --silent

## Technical Stack
- **Language:** Python 3
- **Platform:** Windows / Linux (Kali Optimized)
- **Detection:** Banner Grabbing / Socket Analysis
