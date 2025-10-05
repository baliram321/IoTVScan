import json
import os
from datetime import datetime
from typing import List, Dict
from jinja2 import Template
from smap.utils import Colors

class Results:
    @staticmethod
    def save_json_report(results: List[Dict], filename: str) -> None:
        try:
            with open(filename, 'w') as f:
                json.dump({'scan_time': datetime.now().isoformat(), 'results': results}, f, indent=2)
            print(f"{Colors.GREEN}[SAVED]{Colors.RESET} JSON report saved to {filename}")
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to save JSON report: {e}")

    @staticmethod
    def save_html_report(results: List[Dict], filename: str) -> str:
        template = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>SMAP IoT Device Scan Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background-color: #f9f9f9; }
                h1 { color: #2c3e50; text-align: center; }
                h2 { color: #34495e; }
                h3 { color: #4a6a8a; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                th, td { border: 1px solid #ddd; padding: 12px; text-align: left; }
                th { background-color: #2c3e50; color: white; }
                tr:nth-child(even) { background-color: #f2f2f2; }
                .high { color: #e74c3c; font-weight: bold; }
                .medium { color: #f39c12; font-weight: bold; }
                .summary { background-color: #ecf0f1; padding: 15px; border-radius: 5px; }
                p { margin: 10px 0; }
            </style>
        </head>
        <body>
            <h1>SMAP IoT Vulnerability Scan Report</h1>
            <div class="summary">
                <p><strong>Scan Time:</strong> {{ scan_time }}</p>
                <p><strong>Hosts Scanned:</strong> {{ total_hosts }}</p>
                <p><strong>Open Ports Found:</strong> {{ total_ports }}</p>
                <p><strong>Vulnerabilities Found:</strong> {{ total_vulns }}</p>
            </div>
            {% for host in results %}
            <h2>Host: {{ host.ip }} {% if host.hostname %}({{ host.hostname }}){% endif %}</h2>
            <p><strong>OS Guess:</strong> {{ host.os_guess }}</p>
            <p><strong>Device Type:</strong> {{ host.device_type }}</p>
            {% if host.ports %}
            <h3>Open Ports</h3>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>State</th>
                    <th>Service</th>
                    <th>Version</th>
                    <th>Banner</th>
                </tr>
                {% for port in host.ports %}
                <tr>
                    <td>{{ port.port }}</td>
                    <td>{{ port.protocol }}</td>
                    <td>{{ port.state }}</td>
                    <td>{{ port.service }}</td>
                    <td>{{ port.version }}</td>
                    <td>{{ port.banner | truncate(40) }}</td>
                </tr>
                {% endfor %}
            </table>
            {% endif %}
            {% if host.vulnerabilities %}
            <h3>Vulnerabilities</h3>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Vulnerability</th>
                    <th>Description</th>
                    <th>Severity</th>
                    <th>Recommendation</th>
                </tr>
                {% for vuln in host.vulnerabilities %}
                <tr>
                    <td>{{ vuln.port }}</td>
                    <td>{{ vuln.vulnerability }}</td>
                    <td>{{ vuln.description }}</td>
                    <td class="{{ vuln.severity }}">{{ vuln.severity | capitalize }}</td>
                    <td>{{ vuln.recommendation }}</td>
                </tr>
                {% endfor %}
            </table>
            {% endif %}
            {% endfor %}
            {% if not results %}
            <p>No hosts with open ports or vulnerabilities found.</p>
            {% endif %}
        </body>
        </html>
        """
        jinja_template = Template(template)
        total_hosts = len(results)
        total_ports = sum(len(host['ports']) for host in results)
        total_vulns = sum(len(host.get('vulnerabilities', [])) for host in results)
        try:
            with open(filename, 'w') as f:
                f.write(jinja_template.render(
                    scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    total_hosts=total_hosts,
                    total_ports=total_ports,
                    total_vulns=total_vulns,
                    results=results,
                    truncate=lambda s, n: s[:n] + '...' if len(s) > n else s
                ))
            html_report_path = os.path.abspath(filename)
            html_report_url = f"file://{html_report_path}"
            print(f"{Colors.GREEN}[SAVED]{Colors.RESET} HTML report saved to {html_report_path}")
            print(f"{Colors.BLUE}[VIEW]{Colors.RESET} View HTML report: {html_report_url}")
            return html_report_url
        except Exception as e:
            print(f"{Colors.RED}[ERROR]{Colors.RESET} Failed to save HTML report: {e}")
            return ''