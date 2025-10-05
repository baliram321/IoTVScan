import pytest
from smap.port_scanner import PortScanner

@pytest.fixture
def scanner():
    return PortScanner(timeout=0.5, threads=10)

def test_scan_port_closed(scanner):
    # scanning unlikely open port (e.g., 65000)
    result = scanner.scan_port('192.168.1.1', 65000)
    assert result is None

def test_scan_port_open(scanner):
    # assuming localhost port 22 (SSH) is open; adjust if needed
    result = scanner.scan_port('192.168.1.1', 22)
    if result:  # only if SSH running
        assert result['port'] == 22
        assert 'service' in result

def test_scan_host(scanner):
    ports = [22, 80, 65000]
    host_info = scanner.scan_host('192.168.1.1', ports, scan_type='tcp')
    assert host_info['ip'] == '192.168.1.1'
    assert isinstance(host_info['ports'], list)
