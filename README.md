# Sentinel Ultimate v7.0 

**Sentinel Ultimate** is a high-speed network intelligence tool designed for Kali Linux and security enthusiasts. It efficiently scans subnets, identifies active hosts, resolves hostnames, and audits critical open ports.

## Key Features
- **Multi-threaded Engine:** Powered by `ThreadPoolExecutor` for rapid network discovery.
- **Service Auditing:** Checks for common administrative ports: SSH, HTTP, HTTPS, SMB, RDP, and more.
- **Anti-Block Telegram Delivery:** Implements a multi-stage routing system (Direct, Proxy Mirrors, or personal Cloudflare Workers) to bypass ISP restrictions and DPI.
- **Persistent Logging:** Automatically saves every scan session to `scan_history.log`.
# INSTALL requirements: pip install requests
# 1. Clone the repository
git clone https://github.com/agitd/sentinel-ultimate.git

# 2. Enter the project folder
cd sentinel-ultimate

# 3. Install the required library
pip install requests

# 4. Run the scanner
python3 sentinel.py
