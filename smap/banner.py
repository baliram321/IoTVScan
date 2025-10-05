from smap.utils import Colors

def print_banner():
    banner = f"""{Colors.CYAN}{Colors.BOLD}
███████╗███╗   ███╗ █████╗ ██████╗ 
██╔════╝████╗ ████║██╔══██╗██╔══██╗
███████╗██╔████╔██║███████║██████╔╝
╚════██║██║╚██╔╝██║██╔══██║██╔═══╝ 
███████║██║ ╚═╝ ██║██║  ██║██║     
╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
{Colors.RESET}
{Colors.YELLOW}SMAP - IoT Vulnerability Scanner v1.1 with WhatWeb, Default Credential Checks, TCP & UDP scan{Colors.RESET}
{Colors.GREEN}Network Security Scanner for IoT Devices{Colors.RESET}
"""
    print(banner)