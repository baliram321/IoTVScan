import pytest
from smap.scanner import SmapScanner

@pytest.fixture
def smap_scanner():
    return SmapScanner()

def test_scan_network_localhost(smap_scanner):
    results = smap_scanner.scan_network('127.0.0.1', '22,80', scan_type='tcp')
    assert isinstance(results, list)
    for host in results:
        assert 'ip' in host
        assert 'ports' in host
        assert isinstance(host['ports'], list)
