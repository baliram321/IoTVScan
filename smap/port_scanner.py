import socket
import subprocess
import re
import base64
import urllib.request
import urllib.error
import urllib.parse
import ssl
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from smap.utils import Colors

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

class PortScanner:
    """Core port scanning functionality"""

    def __init__(self, timeout: float = 1.0, threads: int = 100):
        self.timeout = timeout
        self.threads = threads
        self.common_ports = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
            110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S',
            1883: 'MQTT', 5672: 'AMQP', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            9000: 'HTTP-Admin', 1900: 'UPnP', 5353: 'mDNS', 8883: 'MQTT-SSL',
            8086: 'InfluxDB', 5683: 'CoAP', 5684: 'CoAPS', 161: 'SNMP',
            162: 'SNMP-Trap', 502: 'Modbus', 5000: 'UPnP-Device', 49152: 'Samsung-TV',
            554: 'RTSP', 8554: 'RTSP-Alt', 37777: 'Dahua-DVR', 34567: 'Hikvision',
            9999: 'Telnet-Alt', 35000: 'Camera-Admin'
        }

    def scan_port(self, host: str, port: int) -> Optional[Dict]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                if result == 0:
                    service = self.identify_service(host, port)
                    banner = self.grab_banner(host, port)
                    return {
                        'port': port,
                        'state': 'open',
                        'service': service.get('name', self.common_ports.get(port, 'unknown')),
                        'version': service.get('version', ''),
                        'banner': banner,
                        'protocol': 'tcp'
                    }
        except Exception:
            pass
        return None

    def scan_udp_port(self, host: str, port: int) -> Optional[Dict]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                probe = b''
                if port == 53:
                    probe = base64.b16decode('AAABAAABAAAA000100000000000000000377777706676F6F676C6503636F6D0000010001', casefold=True)
                elif port == 161:
                    probe = base64.b16decode('300c02010104067075626c696ca004020700020100020100', casefold=True)
                sock.sendto(probe, (host, port))
                try:
                    data, _ = sock.recvfrom(1024)
                    return {
                        'port': port,
                        'state': 'open',
                        'service': self.common_ports.get(port, 'unknown'),
                        'version': '',
                        'banner': data.decode('utf-8', errors='ignore').strip()[:200],
                        'protocol': 'udp'
                    }
                except socket.timeout:
                    return {
                        'port': port,
                        'state': 'open|filtered',
                        'service': self.common_ports.get(port, 'unknown'),
                        'version': '',
                        'banner': '',
                        'protocol': 'udp'
                    }
        except Exception:
            return None

    def grab_banner(self, host: str, port: int) -> str:
        try:
            with socket.create_connection((host, port), timeout=2.0) as sock:
                if port in [443, 8443]:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with context.wrap_socket(sock, server_hostname=host) as ssock:
                        ssock.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                        banner = b''
                        try:
                            banner = ssock.recv(1024)
                        except socket.timeout:
                            pass
                        return banner.decode('utf-8', errors='ignore').strip()[:200]
                else:
                    sock.settimeout(2.0)
                    if port in [80, 8080]:
                        sock.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                    elif port == 25:
                        sock.sendall(b"EHLO example.com\r\n")
                    banner = b''
                    try:
                        banner = sock.recv(1024)
                    except socket.timeout:
                        pass
                    return banner.decode('utf-8', errors='ignore').strip()[:200]
        except Exception:
            return ''

    def identify_service(self, host: str, port: int) -> Dict:
        service_info = {'name': 'unknown', 'version': ''}
        try:
            banner = self.grab_banner(host, port)
            if port in [80, 443, 8080, 8443]:
                whatweb_result = self.run_whatweb(host, port)
                if whatweb_result:
                    for detection in whatweb_result.get('plugins', []):
                        name = detection.get('name')
                        version = detection.get('version') or ''
                        if name:
                            service_info = {'name': name, 'version': version}
                            break
                if service_info['name'] == 'unknown':
                    service_info.update(self.detect_http_service(host, port))
            elif port == 22 or 'SSH' in banner:
                if 'OpenSSH' in banner:
                    version_match = re.search(r'OpenSSH_([^\s]+)', banner)
                    if version_match:
                        service_info = {'name': 'OpenSSH', 'version': version_match.group(1)}
            elif port == 21 or 'FTP' in banner:
                if 'vsftpd' in banner:
                    version_match = re.search(r'vsftpd ([^\s]+)', banner)
                    if version_match:
                        service_info = {'name': 'vsftpd', 'version': version_match.group(1)}
            elif port == 23:
                service_info = {'name': 'Telnet', 'version': ''}
            elif port in [1883, 8883]:
                service_info = {'name': 'MQTT', 'version': ''}
        except Exception:
            pass
        return service_info

    def run_whatweb(self, host: str, port: int) -> Optional[Dict]:
        try:
            scheme = 'https' if port in [443, 8443] else 'http'
            target_url = f"{scheme}://{host}:{port}/"
            result = subprocess.run(
                ['whatweb', '-q', '-a', '3', '--log-json', '-', target_url],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0 and result.stdout:
                lines = result.stdout.strip().split('\n')
                if lines:
                    for line in lines:
                        try:
                            data = json.loads(line)
                            if 'plugins' in data:
                                return data
                        except json.JSONDecodeError:
                            continue
        except Exception:
            pass
        return None

    def detect_http_service(self, host: str, port: int) -> Dict:
        try:
            protocol = 'https' if port in [443, 8443] else 'http'
            url = f"{protocol}://{host}:{port}/"
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'SMAP/1.0')
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            if protocol == 'https':
                with urllib.request.urlopen(req, timeout=3, context=context) as response:
                    headers = dict(response.headers)
            else:
                with urllib.request.urlopen(req, timeout=3) as response:
                    headers = dict(response.headers)
            server = headers.get('Server', '')
            if 'nginx' in server.lower():
                version_match = re.search(r'nginx/([^\s]+)', server)
                return {'name': 'nginx', 'version': version_match.group(1) if version_match else ''}
            elif 'apache' in server.lower():
                version_match = re.search(r'Apache/([^\s]+)', server)
                return {'name': 'Apache', 'version': version_match.group(1) if version_match else ''}
            elif 'lighttpd' in server.lower():
                return {'name': 'lighttpd', 'version': ''}
            elif server:
                return {'name': server, 'version': ''}
        except Exception:
            pass
        return {'name': 'HTTP', 'version': ''}

    def scan_host(self, host: str, ports: List[int], scan_type: str = 'tcp') -> Dict:
        print(f"{Colors.CYAN}[INFO]{Colors.RESET} Scanning {host} [{scan_type.upper()}]...")
        host_info = {
            'ip': host,
            'hostname': self.resolve_hostname(host),
            'ports': [],
            'os_guess': '',
            'device_type': 'unknown'
        }
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            if scan_type == 'tcp':
                future_to_port = {executor.submit(self.scan_port, host, port): port for port in ports}
            elif scan_type == 'udp':
                future_to_port = {executor.submit(self.scan_udp_port, host, port): port for port in ports}
            elif scan_type == 'both':
                futures = []
                for port in ports:
                    futures.append(executor.submit(self.scan_port, host, port))
                    futures.append(executor.submit(self.scan_udp_port, host, port))
                future_to_port = {f: i for i, f in enumerate(futures)}
            else:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Unknown scan type: {scan_type}")
                return host_info
            for future in as_completed(future_to_port):
                result = future.result()
                if result:
                    host_info['ports'].append(result)
        host_info['ports'].sort(key=lambda x: (x['port'], x['protocol']))
        if host_info['ports']:
            host_info['os_guess'] = self.guess_os(host_info['ports'])
            host_info['device_type'] = self.guess_device_type(host_info['ports'])
        return host_info

    def resolve_hostname(self, ip: str) -> str:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return ''

    def guess_os(self, ports: List[Dict]) -> str:
        port_numbers = [p['port'] for p in ports if p['protocol'] == 'tcp']
        if 22 in port_numbers:
            for p in ports:
                if p['port'] == 22 and 'openssh' in p.get('banner', '').lower():
                    return 'Linux'
        if any(p in port_numbers for p in [135, 139, 445, 3389]):
            return 'Windows'
        if any(p in port_numbers for p in [23, 80, 8080]) and not any(p in port_numbers for p in [22, 135, 445]):
            return 'Embedded/IoT'
        return 'Unknown'

    def guess_device_type(self, ports: List[Dict]) -> str:
        port_numbers = [p['port'] for p in ports]
        if any(p in port_numbers for p in [554, 8554, 37777, 34567]):
            return 'IP Camera'
        if any(p in port_numbers for p in [80, 443, 23, 161]) and len(port_numbers) >= 3:
            return 'Router/Gateway'
        if any(p in port_numbers for p in [1883, 5683, 8086]):
            return 'IoT Sensor'
        if 49152 in port_numbers:
            return 'Smart TV'
        if any(p in port_numbers for p in [80, 443, 8080, 8443]):
            return 'Web Server'
        return 'Unknown Device'