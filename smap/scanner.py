import time
from typing import Dict, List, Optional
from smap.port_scanner import PortScanner
from smap.vulnerability import VulnerabilityScanner
from smap.results import Results
from smap.utils import Colors, parse_targets, parse_ports, is_host_up

class SmapScanner:
    def __init__(self):
        self.port_scanner = PortScanner()
        self.vuln_scanner = VulnerabilityScanner()
        self.results_handler = Results()

    def print_host_results(self, host_result: Dict):
        print(f"\n{Colors.GREEN}{Colors.BOLD}Host: {host_result['ip']}{Colors.RESET}")
        if host_result['hostname']:
            print(f"Hostname: {host_result['hostname']}")
        print(f"OS Guess: {host_result['os_guess']}")
        print(f"Device Type: {host_result['device_type']}")
        if host_result['ports']:
            print(f"\n{Colors.BLUE}Open Ports:{Colors.RESET}")
            print(f"{'PORT':<8} {'PROTO':<6} {'STATE':<12} {'SERVICE':<20} {'VERSION':<20} {'BANNER'}")
            print("-" * 110)
            for port in host_result['ports']:
                banner = port['banner'][:40] + '...' if len(port['banner']) > 40 else port['banner']
                print(f"{port['port']:<8} {port['protocol']:<6} {port['state']:<12} {port['service']:<20} {port['version']:<20} {banner}")
        if host_result.get('vulnerabilities'):
            print(f"\n{Colors.RED}Vulnerabilities Found:{Colors.RESET}")
            for vuln in host_result['vulnerabilities']:
                severity_color = Colors.RED if vuln['severity'] == 'high' else Colors.YELLOW
                print(f"  {severity_color}• Port {vuln['port']}: {vuln['description']}{Colors.RESET}")
                print(f"     Severity: {vuln['severity'].upper()}")
                if 'service' in vuln:
                    print(f"     Service: {vuln['service']}")
                print(f"     Recommendation: {vuln['recommendation']}")
        print("-" * 110)

    def print_summary(self, results: List[Dict], scan_time: float):
        total_hosts = len(results)
        total_ports = sum(len(host['ports']) for host in results)
        total_vulns = sum(len(host.get('vulnerabilities', [])) for host in results)
        print(f"\n{Colors.CYAN}{Colors.BOLD}Scan Summary:{Colors.RESET}")
        print(f"Hosts scanned: {total_hosts}")
        print(f"Open ports found: {total_ports}")
        print(f"Vulnerabilities found: {total_vulns}")
        print(f"Scan time: {scan_time:.2f} seconds")
        if total_vulns > 0:
            print(f"\n{Colors.RED}⚠️  Security Issues Detected!{Colors.RESET}")
            print(f"Review the vulnerabilities above and apply recommended fixes.")

    def scan_network(self, target: str, ports: str, default_creds: Optional[Dict] = None, scan_type: str = 'tcp') -> List[Dict]:
        print(f"{Colors.BLUE}[SCAN]{Colors.RESET} Starting scan of {target}")
        print(f"{Colors.BLUE}[SCAN]{Colors.RESET} Ports: {ports}")
        print(f"{Colors.BLUE}[SCAN]{Colors.RESET} Type: {scan_type.upper()}")
        print("-" * 60)
        hosts = parse_targets(target)
        port_list = parse_ports(ports, self.port_scanner.common_ports)
        print(f"{Colors.CYAN}[INFO]{Colors.RESET} Scanning {len(hosts)} hosts on {len(port_list)} ports")
        results = []
        start_time = time.time()
        for host in hosts:
            try:
                if is_host_up(host):
                    host_result = self.port_scanner.scan_host(host, port_list, scan_type=scan_type)
                    if host_result['ports']:
                        host_result['vulnerabilities'] = self.vuln_scanner.scan_vulnerabilities(host_result, default_creds)
                        results.append(host_result)
                        self.print_host_results(host_result)
                else:
                    print(f"{Colors.RED}[DOWN]{Colors.RESET} {host} appears to be down")
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[CTRL+C]{Colors.RESET} Scan interrupted by user")
                break
            except Exception as e:
                print(f"{Colors.RED}[ERROR]{Colors.RESET} Error scanning {host}: {e}")
        end_time = time.time()
        self.print_summary(results, end_time - start_time)
        return results

    def save_results(self, results: List[Dict], filename: str, format: str = 'json'):
        if format.lower() == 'json':
            self.results_handler.save_json_report(results, filename)
        elif format.lower() == 'html':
            self.results_handler.save_html_report(results, filename)