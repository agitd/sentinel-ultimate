import asyncio
import socket
import logging
import aiohttp
from scapy.all import ARP, Ether, srp, conf
from typing import Dict, List, Optional

# Импорты модулей
from config.settings import PORTS_TO_CHECK
from core.fingerprint import OSFingerprinting
from core.auth_scanner import check_ssh_login

# Полное подавление логов, чтобы не было мусора
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
try:
    import paramiko
    logging.getLogger("paramiko").setLevel(logging.CRITICAL)
except ImportError:
    pass

semaphore = asyncio.Semaphore(500)

async def check_smbv1(ip: str) -> bool:
    """
    Проверка SMBv1. Пакет упакован в hex, чтобы избежать SyntaxError.
    """
    try:
        hex_payload = (
            "00000085ff534d4272000000001853c80000000000000000000000000000fffe"
            "00004000006200025043204e4554574f524b2050524f4752414d20312e3000"
            "024c414e4d414e312e30000257494e444f575320464f5220574f524b47524f"
            "55505320332e316100024c414e4d312e325830303200024c414e4d414e322e"
            "3100024e54204c4d20302e313200"
        )
        smb_packet = bytes.fromhex(hex_payload)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 445), timeout=2)
        writer.write(smb_packet)
        await writer.drain()
        response = await asyncio.wait_for(reader.read(1024), timeout=2)
        writer.close()
        await writer.wait_closed()
        return b'\xffSMB\x72' in response
    except:
        return False

async def get_cves(service_version: str, os_hint: str = "") -> List[str]:
    if not service_version or len(service_version) < 3 or service_version == "unk":
        return []
    query = service_version.split()[0].lower().replace("(", "").replace(")", "")
    url = f"https://cve.circl.lu/api/search/{query}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    res = []
                    for item in data[:5]:
                        summ = item.get('summary', '').lower()
                        if os_hint.lower() == "linux" and "windows" in summ: continue
                        if os_hint.lower() == "windows" and "linux" in summ: continue
                        res.append(item.get('id'))
                    return res[:2]
    except: pass
    return []

async def get_service_info(ip: str, port: int) -> Optional[Dict]:
    async with semaphore:
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2.0)
            banner = ""
            try:
                data = await asyncio.wait_for(reader.read(256), timeout=1.5)
                banner = data.decode(errors='ignore').strip()
            except: pass
            writer.close()
            await writer.wait_closed()
            return {"port": port, "ver": banner if banner else "unk"}
        except: return None

async def scan_host(ip_str: str) -> Optional[Dict]:
    tasks = [get_service_info(ip_str, p) for p in PORTS_TO_CHECK.keys()]
    probes = await asyncio.gather(*tasks)
    found_data = [p for p in probes if p]
    if not found_data: return None

    try: name = socket.gethostbyaddr(ip_str)[0]
    except: name = "no-name"

    p_found = [p['port'] for p in found_data]
    banners = {p['port']: p['ver'] for p in found_data}
    os_g, os_c = OSFingerprinting.guess_os(ip_str, p_found, banners)

    services, cve_all = [], []
    if 445 in p_found and await check_smbv1(ip_str):
        services.append("445(SMB) [VULN: SMBv1 Enabled!]")
        cve_all.append("SMBv1-Vulnerability")

    for p in found_data:
        lbl = PORTS_TO_CHECK.get(p['port'], "unk")
        clist = await get_cves(p['ver'], os_hint=os_g)
        cve_all.extend(clist)
        cinfo = f" [CVE: {', '.join(clist)}]" if clist else ""
        ainfo = ""
        if p['port'] == 22:
            creds = await check_ssh_login(ip_str, p['port'])
            if creds:
                ainfo = f" [VULN: SSH Weak {creds}]"
                cve_all.append(f"SSH-Weak-{creds}")
        if p['port'] == 445 and "SMBv1" in "".join(services): continue
        services.append(f"{p['port']}({lbl}){cinfo}{ainfo}")

    return {
        "ip": ip_str, "name": name, "os": f"{os_g} ({os_c}%)",
        "ports": ", ".join(services), "cves": ", ".join(list(set(cve_all))),
        "tg_row": f"  {ip_str.ljust(15)} | *{name[:12]}* | {os_g} | {len(services)} ports"
    }

def get_active_hosts_arp(network: str) -> list:
    try:
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, verbose=False)
        return list(set([received.psrc for sent, received in ans]))
    except: return []

async def scan_network(network: str) -> List[Dict]:
    if "/" not in network:
        r = await scan_host(network)
        return [r] if r else []
    ips = get_active_hosts_arp(network)
    if not ips: return []
    tasks = [scan_host(ip) for ip in ips]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r]

