import pytest
from smap.utils import parse_targets, parse_ports, is_host_up

def test_parse_targets():
    targets = parse_targets("127.0.0.1")
    assert targets == ["127.0.0.1"]

def test_parse_ports():
    ports = parse_ports("22,80", {})
    assert 22 in ports and 80 in ports

def test_is_host_up(monkeypatch):
    monkeypatch.setattr("socket.socket.connect_ex", lambda self, addr: 0)
    assert is_host_up("127.0.0.1")
