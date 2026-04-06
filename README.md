# Sentinel Ultimate v9.0

**Sentinel Ultimate** is a high-speed, professional-grade network intelligence tool designed for Kali Linux and security enthusiasts. Version 9.0 features an expanded database of 200+ critical service ports and enhanced multi-threaded performance.

## Key Features
- **Elite Service Detection (200+ Ports):** Comprehensive scanning across Web, Databases, Cloud/Containers, DevOps tools, and Monitoring systems.
- **Deep Banner Grabbing:** Identifies specific versions of services (SSH, HTTP headers, etc.) for vulnerability assessment.
- **High-Velocity Engine:** Optimized `ThreadPoolExecutor` with a default of 100 threads for rapid subnet discovery.
- **Cross-Platform Core:** Native support for Windows, Linux, and macOS with intelligent OS detection.
- **Enterprise Reporting:** Simultaneous delivery to Telegram (with Cloudflare bypass) and Slack webhooks.
- **Data Persistence:** Auto-timestamped exports in JSON/CSV and persistent logging via `scan_history.log`.

# INSTALL requirements: pip install -r requirements.txt

# 1. Clone the repository
git clone https://github.com/agitd/sentinel-ultimate.git

# 2. Enter the project folder
cd sentinel-ultimate

# 3. Install the required libraries
pip install -r requirements.txt

# 4. Run the scanner
# Note: Ensure your .env file is configured in the root directory
python3 Sentinel.py -n 192.168.1.0/24

Usage (Аргументы запуска)

Sentinel Ultimate v9.0 supports advanced CLI arguments for granular control:

| Flag | Description | Example |
| :--- | :--- | :--- |
| `-n` | **Network** (Required CIDR) | `-n 192.168.1.0/24` |
| `-t` | **Threads** (Default: 100) | `-t 200` |
| `-f` | **Format** (json/csv) | `-f json` |
| `--silent` | **Disable Notifications** | `--silent` |
| `-h` | **Show Help Menu** | `-h` |

### Examples:

# Basic scan with version detection and remote reporting
python3 Sentinel.py -n 192.168.1.0/24

# High-speed scan (200 threads) with CSV export
python3 Sentinel.py -n 10.0.0.0/16 -t 200 -f csv

# Access full help menu and usage examples
python3 Sentinel.py -h

## Scanned Categories (200+ Services)
* **Web:** Node.js, Flask, Tomcat, Dev Servers
* **Databases:** MySQL, Postgres, MongoDB, Redis, Cassandra, Elasticsearch
* **Cloud:** Docker, Kubernetes, Consul, Etcd
* **DevOps:** Jenkins, GitLab, SonarQube, Nexus, Artifactory
* **Monitoring:** Prometheus, Grafana, Splunk, InfluxDB
