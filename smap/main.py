#!/usr/bin/env python3
"""
SMAP - IoT Vulnerability Scanner
A Python-based network scanner for IoT devices similar to nmap
Uses WhatWeb tool for enhanced HTTP service version detection and default credential checks
"""
import argparse
import sys
import json
from typing import Dict, List, Optional
from smap.banner import print_banner
from smap.scanner import SmapScanner
from smap.utils import Colors

def main():
    parser = argparse.ArgumentParser(
        description='SMAP - IoT Vulnerability Scanner with Default Credential Checking',
        epilog='''
Examples:
  python -m smap 192.168.1.1 -p common -d creds/default_creds.json
  python -m smap 192.168.1.0/24 -p 22,80,443 -d creds/default_creds.json -o results.json
  python -m smap 192.168.1.0/24 -p 53,161 -sU
  python -m smap 192.168.1.0/24 -p common -sT
        ''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('target', help='Target host(s) to scan (IP, CIDR, or range)')
    parser.add_argument('-p', '--ports', default='common', help='Ports to scan (default: common, options: all, common, 1-1000, 22,80,443)')
    parser.add_argument('-t', '--timeout', type=float, default=1.0, help='Timeout for connections (default: 1.0)')
    parser.add_argument('--threads', type=int, default=100, help='Number of threads to use (default: 100)')
    parser.add_argument('-o', '--output', help='Output file for JSON results')
    parser.add_argument('-f', '--format', default='json', choices=['json'], help='Output format (default: json)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-d', '--default-creds', help='JSON file with default credentials for services (e.g., creds/default_creds.json)')
    parser.add_argument('--html', action='store_true', help='Generate HTML report')
    scan_group = parser.add_mutually_exclusive_group()
    scan_group.add_argument('-sU', action='store_true', help='Scan UDP ports instead of TCP (default: TCP)')
    scan_group.add_argument('-sT', action='store_true', help='Scan TCP ports (default)')
    args = parser.parse_args()

    scan_type = 'udp' if args.sU else 'tcp'
    default_creds = None
    if args.default_creds:
        try:
            with open(args.default_creds, 'r') as f:
                default_creds = json.load(f)
            default_creds = {k.lower(): v for k, v in default_creds.items()}
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Could not load default credentials file: {e}")
            sys.exit(1)

    scanner = SmapScanner()
    scanner.port_scanner.timeout = args.timeout
    scanner.port_scanner.threads = args.threads
    print_banner()

    try:
        results = scanner.scan_network(args.target, args.ports, default_creds, scan_type=scan_type)
        if args.output:
            scanner.save_results(results, args.output, format=args.format)
        if args.html:
            scanner.save_results(results, 'scan_report.html', format='html')
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[CTRL+C]{Colors.RESET} Scan interrupted by user")
    except Exception as e:
        print(f"{Colors.RED}[ERROR]{Colors.RESET} Scan failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()