import pytest
from smap.vulnerability import VulnerabilityScanner

def test_load_vulnerability_signatures():
    scanner = VulnerabilityScanner()
    vulns = scanner.vulnerability_db
    assert "weak_ssh" in vulns
    assert vulns["telnet_open"]["severity"] == "high"

def test_scan_vulnerabilities_with_ssh():
    scanner = VulnerabilityScanner()
    host_info = {
        "ip": "127.0.0.1",
        "ports": [{"port": 22, "service": "ssh", "protocol": "tcp"}]
    }
    vulns = scanner.scan_vulnerabilities(host_info, default_creds=None)
    assert any(v["vulnerability"] == "weak_ssh" for v in vulns)

def test_default_credentials_detection(monkeypatch):
    scanner = VulnerabilityScanner()
    host_info = {
        "ip": "127.0.0.1",
        "ports": [{"port": 21, "service": "ftp", "protocol": "tcp"}]
    }

    # Mock check_default_creds to simulate detection
    monkeypatch.setattr(scanner, "check_default_creds", lambda h, p, c: True)

    vulns = scanner.scan_vulnerabilities(host_info, default_creds={"ftp": [("admin", "admin")]})
    assert any(v["vulnerability"] == "default_credentials" for v in vulns)
