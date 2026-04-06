import pytest
import ipaddress
from Sentinel import OSFingerprinting, PORTS_TO_CHECK

class TestCIDR:
    """Тесты CIDR парсинга"""

    def test_valid_cidrs(self):
        """Тест валидных CIDR нотаций"""
        assert ipaddress.ip_network("192.168.1.0/24").num_addresses == 256
        assert ipaddress.ip_network("10.0.0.0/16").num_addresses == 65536
        assert ipaddress.ip_network("192.168.1.1/32").num_addresses == 1

    def test_invalid_cidrs(self):
        """Тест невалидных CIDR"""
        with pytest.raises(ValueError):
            ipaddress.ip_network("256.256.256.256/24")
        with pytest.raises(ValueError):
            ipaddress.ip_network("192.168.1.0/33")

    def test_hosts_generation(self):
        """Тест генерации IP адресов"""
        hosts = list(ipaddress.ip_network("192.168.1.0/29").hosts())
        assert len(hosts) == 6
        assert str(hosts[0]) == "192.168.1.1"

class TestOS:
    """Тесты OS Fingerprinting"""

    def test_linux(self):
        """Тест Linux определения"""
        os_guess, conf = OSFingerprinting.guess_os("192.168.1.1", [22, 111], {22: "OpenSSH", 111: "Linux"})
        assert os_guess == "Linux"
        assert conf >= 70

    def test_windows(self):
        """Тест Windows определения"""
        os_guess, conf = OSFingerprinting.guess_os("192.168.1.1", [445, 3389], {445: "SMB", 3389: "RDP"})
        assert os_guess == "Windows"
        assert conf >= 70

    def test_docker(self):
        """Тест Docker определения"""
        os_guess, conf = OSFingerprinting.guess_os("192.168.1.1", [2375], {2375: "Docker"})
        assert os_guess == "Docker/Container"

    def test_unknown(self):
        """Тест неизвестной ОС"""
        os_guess, conf = OSFingerprinting.guess_os("192.168.1.1", [], {})
        assert os_guess == "Unknown"
        assert conf == 0

    def test_confidence_range(self):
        """Тест диапазона уверенности"""
        _, conf = OSFingerprinting.guess_os("192.168.1.1", [22, 111], {22: "OpenSSH", 111: "NFS"})
        assert 0 <= conf <= 100

class TestPorts:
    """Тесты портов"""

    def test_200_plus_ports(self):
        """Тест 200+ портов"""
        assert len(PORTS_TO_CHECK) >= 200

    def test_port_values(self):
        """Тест формата портов"""
        for port, label in PORTS_TO_CHECK.items():
            assert isinstance(port, int) and 1 <= port <= 65535
            assert isinstance(label, str) and len(label) > 0

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
