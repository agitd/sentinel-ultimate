import asyncio
import socket
import logging
import aiohttp
from scapy.all import ARP, Ether, srp, conf
from typing import Dict, List, Optional

from config.settings import PORTS_TO_CHECK
from core.fingerprint import OSFingerprinting

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
semaphore = asyncio.Semaphore(500)

async def get_cves(service_version: str) -> List[str]:
    if not service_version or len(service_version) < 3 or service_version == "unk":
        return []

    search_query = service_version.split()[0].lower()
    url = f"https://cve.circl.lu/api/search/{search_query}"

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return [item.get('id') for item in data[:2]]
    except:
        pass
    return []

async def get_service_info(ip: str, port: int) -> Optional[Dict]:
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=2.0
            )
            banner = ""
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=1.5)
                banner = data.decode(errors='ignore').strip()
            except:
                pass
            writer.close()
            await writer.wait_closed()
            return {"port": port, "ver": banner if banner else "unk", "title": ""}
        except:
            return None

async def scan_host(ip_str: str) -> Optional[Dict]:
    tasks = [get_service_info(ip_str, p) for p in PORTS_TO_CHECK.keys()]
    probes = await asyncio.gather(*tasks)
    found_data = [p for p in probes if p]

    if not found_data:
        return None

    try:
        name = socket.gethostbyaddr(ip_str)[0]
    except:
        name = "no-name"

    ports_found = [p['port'] for p in found_data]
    banners = {p['port']: p['ver'] for p in found_data}
    os_g, os_c = OSFingerprinting.guess_os(ip_str, ports_found, banners)

    found_services = []
    for p in found_data:
        label = PORTS_TO_CHECK.get(p['port'], "unk")
        cve_list = await get_cves(p['ver'])
        cve_info = f" [CVE: {', '.join(cve_list)}]" if cve_list else ""
        found_services.append(f"{p['port']}({label}){cve_info}")

    return {
        "ip": ip_str,
        "name": name,
        "os": f"{os_g} ({os_c}%)",
        "ports": ", ".join(found_services),
        "tg_row": f"  {ip_str.ljust(15)} | *{name[:12]}* | {os_g} | {len(found_services)} ports"
    }

def get_active_hosts_arp(network: str) -> list:
    try:
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        result = srp(ether/arp, timeout=2, retry=2, verbose=False)[0]
        return list(set([received.psrc for sent, received in result]))
    except Exception as e:
        print(f"[-] ARP Error: {e}")
        return []

async def scan_network(network: str) -> List[Dict]:
    print(f"[*] Starting ARP scan for {network}...")
    ips = get_active_hosts_arp(network)
    if not ips: return []
    print(f"[+] Found {len(ips)} alive hosts. Scanning services...")
    tasks = [scan_host(ip) for ip in ips]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r]

