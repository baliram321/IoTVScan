import pytest
from smap.scanner import SmapScanner
from smap.port_scanner import PortScanner
from smap.vulnerability import VulnerabilityScanner

def test_full_scan(monkeypatch):
    # Patch PortScanner.scan_host for this test only
    def fake_scan_host(self, host, ports, scan_type='tcp'):
        return {
            'ip': host,
            'hostname': 'localhost',
            'ports': [
                {'port': 22, 'state': 'open', 'service': 'SSH', 'version': '', 'banner': '', 'protocol': 'tcp'}
            ],
            'os_guess': 'Linux',
            'device_type': 'Server'
        }

    monkeypatch.setattr(PortScanner, "scan_host", fake_scan_host)

    # Patch VulnerabilityScanner.scan_vulnerabilities
    def fake_scan_vulnerabilities(self, host_info, default_creds=None):
        return [{
            'port': 22,
            'vulnerability': 'weak_ssh',
            'description': 'SSH detected - weak',
            'severity': 'medium',
            'recommendation': 'Use key-based auth'
        }]

    monkeypatch.setattr(VulnerabilityScanner, "scan_vulnerabilities", fake_scan_vulnerabilities)

    scanner = SmapScanner()
    results = scanner.scan_network("127.0.0.1", "22", scan_type='tcp')

    assert len(results) == 1
    host_result = results[0]
    assert host_result['ip'] == "127.0.0.1"
    assert host_result['ports'][0]['port'] == 22
    assert len(host_result['vulnerabilities']) == 1
