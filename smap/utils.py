import socket
import ipaddress
import subprocess
from typing import List

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'

def parse_targets(target: str) -> List[str]:
    hosts = []
    try:
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            hosts = [str(ip) for ip in network.hosts()]
        elif '-' in target and '.' in target:
            base_ip, range_part = target.rsplit('.', 1)
            if '-' in range_part:
                start, end = map(int, range_part.split('-'))
                hosts = [f"{base_ip}.{i}" for i in range(start, end + 1)]
            else:
                hosts = [target]
        else:
            hosts = [target]
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.RESET} Invalid target format: {e}")
        raise
    return hosts

def parse_ports(ports: str, common_ports: dict) -> List[int]:
    port_list = []
    if ports.lower() == 'common':
        port_list = list(common_ports.keys())
    elif ports.lower() == 'all':
        port_list = list(range(1, 65536))
    else:
        try:
            for port_spec in ports.split(','):
                if '-' in port_spec:
                    start, end = map(int, port_spec.split('-'))
                    port_list.extend(range(start, end + 1))
                else:
                    port_list.append(int(port_spec))
        except ValueError:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Invalid port specification")
            raise
    return sorted(list(set(port_list)))

def is_host_up(host: str) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((host, 80))
            if result == 0:
                return True
        result = subprocess.run(['ping', '-c', '1', '-W', '1', host], capture_output=True, text=True)
        return result.returncode == 0
    except Exception:
        return True