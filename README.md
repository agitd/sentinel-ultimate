# Sentinel Ultimate v7.2

**Sentinel Ultimate** is a high-speed network intelligence tool designed for Kali Linux and security enthusiasts. It efficiently scans subnets, identifies active hosts, resolves hostnames, and audits critical open ports. Now with full cross-platform support.

## Key Features
- **Multi-threaded Engine:** Powered by `ThreadPoolExecutor` for rapid network discovery.
- **Service Auditing:** Checks for common administrative ports: SSH, HTTP, HTTPS, SMB, RDP, and more.
- **Cross-Platform Support (New!):** Automatically detects OS (Windows/Linux) and adjusts scanning logic.
- **Anti-Block Telegram Delivery:** Implements a multi-stage routing system (Direct, Proxy Mirrors, or personal Cloudflare Workers).
- **Advanced Export:** Save scan results with timestamps in JSON or CSV formats.
- **Persistent Logging:** Automatically saves every scan session to `scan_history.log`.

## Installation & Usage

# 1. Clone the repository
git clone https://github.com/agitd/sentinel-ultimate.git

# 2. Enter the project folder
cd sentinel-ultimate

# 3. Install the required library
pip install requests

# 4. Configuration (v7.2)
# Copy the environment template and add your Telegram credentials
cp env.example .env

# 5. Run the scanner
python3 Sentinel.py -n 192.168.1.0/24

## CLI Arguments

| Flag | Description | Example |
| :--- | :--- | :--- |
| `-n` | **Network** (Required) | `-n 192.168.1.0/24` |
| `-t` | **Threads** (Default: 60) | `-t 100` |
| `-f` | **Format** (json/csv) | `-f json` |
| `--silent`| **No Telegram** | `--silent` |

### Examples:
```bash
# Basic scan (Auto-detects Windows/Linux)
python3 Sentinel.py -n 192.168.1.0/24

# Scan and save to CSV with timestamps
python3 Sentinel.py -n 192.168.1.0/24 -f csv

# Fast scan without Telegram notifications
python3 Sentinel.py -n 10.0.0.0/24 -t 120 --silent
