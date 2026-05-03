import sys
import os
import pytest
import asyncio
import ipaddress

# Фикс путей: принудительно добавил корень проекта
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.fingerprint import OSFingerprinting
from config.settings import PORTS_TO_CHECK

# Импорты для 13.6
try:
    from core.arp_scanner import scan_host, get_cves, check_smbv1
except ImportError:
    pass

class TestCIDR:
    """Тесты CIDR парсинга (v13.5)"""
    def test_valid_cidrs(self):
        assert ipaddress.ip_network("192.168.1.0/24").num_addresses == 256
        assert ipaddress.ip_network("10.0.0.0/16").num_addresses == 65536
        assert ipaddress.ip_network("192.168.1.1/32").num_addresses == 1

    def test_invalid_cidrs(self):
        with pytest.raises(ValueError):
            ipaddress.ip_network("256.256.256.256/24")

    def test_hosts_generation(self):
        hosts = list(ipaddress.ip_network("192.168.1.0/29").hosts())
        assert len(hosts) == 6
        assert str(hosts[0]) == "192.168.1.1"

class TestOS:
    """Тесты OS Fingerprinting (v13.5)"""
    def test_linux(self):
        os_guess, conf = OSFingerprinting.guess_os("192.168.1.1", [22, 111], {22: "OpenSSH", 111: "Linux"})
        assert os_guess == "Linux"
        assert conf >= 70

    def test_windows(self):
        os_guess, conf = OSFingerprinting.guess_os("192.168.1.1", [445, 3389], {445: "SMB", 3389: "RDP"})
        assert os_guess == "Windows"
        assert conf >= 70

    def test_docker(self):
        os_guess, conf = OSFingerprinting.guess_os("192.168.1.1", [2375], {2375: "Docker"})
        assert os_guess == "Docker/Container"

    def test_unknown(self):
        os_guess, conf = OSFingerprinting.guess_os("192.168.1.1", [], {})
        assert os_guess == "Unknown"

class TestPorts:
    """Тесты портов (v13.5)"""
    def test_200_plus_ports(self):
        assert len(PORTS_TO_CHECK) >= 200

    def test_port_values(self):
        for port, label in PORTS_TO_CHECK.items():
            assert isinstance(port, int) and 1 <= port <= 65535

# --- Секция 13.6 (Известно: может конфликтовать с event loop в 3.13) ---

@pytest.mark.asyncio
class TestSecurityv136:
    """Новые тесты безопасности для Sentinel 13.6"""

    async def test_cve_fetch(self):
        """Проверка получения CVE"""
        cves = await get_cves("OpenSSH 7.4", os_hint="Linux")
        assert isinstance(cves, list)

    async def test_smb_payload(self):
        """Проверка SMBv1 чекера"""
        status = await check_smbv1("127.0.0.1")
        assert status in [True, False]

    async def test_full_scan_structure(self):
        """Проверка полей v13.6"""
        res = await scan_host("127.0.0.1")
        if res:
            assert "cves" in res
            assert "os" in res

def test_deps_check():
    """Проверка критических зависимостей"""
    import paramiko
    import aiohttp
    assert True

if __name__ == "__main__":
    pytest.main([__file__, "-v"])

