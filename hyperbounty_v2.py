#!/usr/bin/env python3
"""
HyperBounty v2.0 - Next Generation Bug Bounty Automation Platform
Author: HyperBounty Team
Version: 2.0.0
Description: Advanced automated reconnaissance and vulnerability discovery platform
"""

import subprocess
import sys
import os
import json
import threading
import time
import argparse
import requests
import concurrent.futures
from datetime import datetime
from pathlib import Path
import socket
from urllib.parse import urljoin, urlparse
import re
import shutil
import hashlib
from typing import List, Dict, Optional
import signal

# Version and metadata
VERSION = "2.0.0"

# ANSI color codes
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class Logger:
    def __init__(self, verbose=False):
        self.verbose = verbose

    def info(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Colors.CYAN}[{timestamp}] [INFO]{Colors.END} {message}")

    def success(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Colors.GREEN}[{timestamp}] [SUCCESS]{Colors.END} {message}")

    def warning(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Colors.YELLOW}[{timestamp}] [WARNING]{Colors.END} {message}")

    def error(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{Colors.RED}[{timestamp}] [ERROR]{Colors.END} {message}")

class ToolChecker:
    def __init__(self, logger):
        self.logger = logger
        self.tools = {
            'subfinder': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
            'httpx': 'go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest',
            'nuclei': 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest',
            'nmap': 'sudo apt install nmap',
            'dirsearch': 'pip3 install dirsearch',
            'waybackurls': 'go install github.com/tomnomnom/waybackurls@latest',
            'assetfinder': 'go install github.com/tomnomnom/assetfinder@latest'
        }

    def check_tool(self, tool_name):
        try:
            result = subprocess.run(['which', tool_name], capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except:
            return False

    def check_all_tools(self):
        missing_tools = []
        self.logger.info("Checking required tools...")

        for tool, install_cmd in self.tools.items():
            if not self.check_tool(tool):
                missing_tools.append((tool, install_cmd))
                self.logger.warning(f"Missing: {tool}")
            else:
                self.logger.success(f"Found: {tool}")

        if missing_tools:
            self.logger.warning(f"Missing {len(missing_tools)} tools:")
            for tool, cmd in missing_tools:
                print(f"  {Colors.YELLOW}• {tool}{Colors.END}: {cmd}")

            response = input(f"\n{Colors.CYAN}Continue anyway? (y/N): {Colors.END}")
            return response.lower() == 'y'
        else:
            self.logger.success("All required tools are installed!")
            return True

class CommandRunner:
    def __init__(self, logger, timeout=30):
        self.logger = logger
        self.timeout = timeout

    def run(self, cmd, silent=False, timeout=None):
        if timeout is None:
            timeout = self.timeout

        if not silent:
            self.logger.info(f"Running: {cmd}")

        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, 
                                  timeout=timeout, errors='ignore')

            if result.returncode == 0:
                return result.stdout.strip()
            else:
                if not silent:
                    self.logger.error(f"Command failed: {cmd}")
                return None

        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timed out: {cmd}")
            return None
        except Exception as e:
            if not silent:
                self.logger.error(f"Command execution failed: {e}")
            return None

class HyperBounty:
    def __init__(self, verbose=False):
        self.logger = Logger(verbose)
        self.runner = CommandRunner(self.logger)
        self.tool_checker = ToolChecker(self.logger)

        self.target = ""
        self.output_dir = ""
        self.results = {
            "target": "",
            "scan_date": datetime.now().isoformat(),
            "subdomains": [],
            "live_hosts": [],
            "open_ports": {},
            "technologies": {},
            "vulnerabilities": [],
            "endpoints": []
        }

    def banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
██╗  ██╗██╗   ██╗██████╗ ███████╗██████╗ ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
██║  ██║╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
███████║ ╚████╔╝ ██████╔╝█████╗  ██████╔╝██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ 
██╔══██║  ╚██╔╝  ██╔═══╝ ██╔══╝  ██╔══██╗██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  
██║  ██║   ██║   ██║     ███████╗██║  ██║██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   
╚═╝  ╚═╝   ╚═╝   ╚═╝     ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝   

🚀 HyperBounty v{VERSION} - Advanced Bug Bounty Automation Platform
{Colors.END}"""
        print(banner)
        print(f"{Colors.WHITE}Target: {Colors.GREEN}{self.target}{Colors.END}")
        print(f"{Colors.WHITE}Output: {Colors.GREEN}{self.output_dir}{Colors.END}")
        print("=" * 80)

    def validate_target(self, target):
        # Remove protocol if present
        target = re.sub(r'^https?://', '', target)

        # Basic domain validation
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}$', target):
            return False

        try:
            socket.gethostbyname(target)
            return True
        except:
            return False

    def create_output_directory(self, target):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_dir = f"hyperbounty_results_{target}_{timestamp}"

        directories = ["subdomains", "live_hosts", "ports", "directories", "vulnerabilities", "reports"]

        for directory in directories:
            os.makedirs(f"{base_dir}/{directory}", exist_ok=True)

        return base_dir

    def subdomain_enumeration(self):
        self.logger.info("🔍 Starting subdomain enumeration...")
        all_subdomains = set()

        # Subfinder
        self.logger.info("Running subfinder...")
        result = self.runner.run(f"subfinder -d {self.target} -silent")
        if result:
            subdomains = [line.strip() for line in result.split('\n') if line.strip()]
            all_subdomains.update(subdomains)
            self.logger.success(f"Subfinder found {len(subdomains)} subdomains")

        # Assetfinder
        self.logger.info("Running assetfinder...")
        result = self.runner.run(f"assetfinder --subs-only {self.target}")
        if result:
            subdomains = [line.strip() for line in result.split('\n') if line.strip()]
            all_subdomains.update(subdomains)
            self.logger.success(f"Assetfinder found {len(subdomains)} subdomains")

        # Certificate Transparency
        self.logger.info("Checking Certificate Transparency...")
        try:
            url = f"https://crt.sh/?q=%.{self.target}&output=json"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                ct_subdomains = set()
                for cert in data:
                    name_value = cert.get('name_value', '')
                    for domain in name_value.split('\n'):
                        domain = domain.strip().replace('*.', '')
                        if domain and self.target in domain:
                            ct_subdomains.add(domain)
                all_subdomains.update(ct_subdomains)
                self.logger.success(f"crt.sh found {len(ct_subdomains)} subdomains")
        except Exception as e:
            self.logger.warning(f"crt.sh failed: {e}")

        # Add common subdomains
        common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 'test', 'blog', 'm']
        for sub in common_subs:
            all_subdomains.add(f"{sub}.{self.target}")

        valid_subdomains = sorted([sub for sub in all_subdomains if sub and self.target in sub])
        self.results['subdomains'] = valid_subdomains

        # Save results
        with open(f"{self.output_dir}/subdomains/all_subdomains.txt", 'w') as f:
            for subdomain in valid_subdomains:
                f.write(f"{subdomain}\n")

        self.logger.success(f"Total unique subdomains found: {len(valid_subdomains)}")
        return valid_subdomains

    def probe_live_hosts(self, subdomains):
        self.logger.info("🌐 Probing for live HTTP services...")

        if not subdomains:
            return []

        # Save subdomains to temp file
        temp_file = f"{self.output_dir}/temp_subdomains.txt"
        with open(temp_file, 'w') as f:
            for subdomain in subdomains:
                f.write(f"{subdomain}\n")

        # Use httpx
        output_file = f"{self.output_dir}/live_hosts/httpx_results.txt"
        cmd = f"httpx -l {temp_file} -silent -o {output_file} -status-code -title"

        result = self.runner.run(cmd)

        live_hosts = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                for line in f:
                    if line.strip():
                        url = line.split()[0]
                        live_hosts.append(url)

            self.results['live_hosts'] = live_hosts
            self.logger.success(f"Found {len(live_hosts)} live hosts")

            # Clean up temp file
            os.remove(temp_file)

            return live_hosts
        else:
            self.logger.warning("No live hosts found")
            return []

    def port_scanning(self, live_hosts):
        self.logger.info("🔌 Starting port scanning...")

        if not live_hosts:
            return

        # Extract hostnames
        hostnames = []
        for host in live_hosts:
            parsed = urlparse(host if host.startswith('http') else f'http://{host}')
            hostname = parsed.netloc or parsed.path
            if hostname and hostname not in hostnames:
                hostnames.append(hostname)

        for hostname in hostnames[:10]:  # Limit for performance
            self.logger.info(f"Scanning ports on {hostname}")

            cmd = f"nmap -Pn -sS -p 80,443,8080,8443,3000,5000 --open {hostname} --min-rate 1000"
            result = self.runner.run(cmd, silent=True)

            if result:
                open_ports = []
                for line in result.split('\n'):
                    if '/tcp' in line and 'open' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port = parts[0].split('/')[0]
                            service = parts[2] if len(parts) > 2 else 'unknown'
                            open_ports.append({'port': port, 'service': service})

                if open_ports:
                    self.results['open_ports'][hostname] = open_ports
                    self.logger.success(f"{hostname}: {len(open_ports)} open ports")

    def technology_detection(self, live_hosts):
        self.logger.info("🔧 Detecting web technologies...")

        for host in live_hosts[:10]:
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (compatible; HyperBounty/2.0)'
                }

                response = requests.get(host, timeout=10, headers=headers, 
                                      verify=False, allow_redirects=True)

                tech_info = {
                    'url': host,
                    'status_code': response.status_code,
                    'server': response.headers.get('Server', 'Unknown'),
                    'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
                    'cms': 'Unknown'
                }

                # Basic CMS detection
                content = response.text.lower()
                if 'wp-content' in content or 'wordpress' in content:
                    tech_info['cms'] = 'WordPress'
                elif 'joomla' in content:
                    tech_info['cms'] = 'Joomla'
                elif 'drupal' in content:
                    tech_info['cms'] = 'Drupal'

                self.results['technologies'][host] = tech_info

            except Exception as e:
                self.logger.warning(f"Technology detection failed for {host}: {e}")

    def directory_discovery(self, live_hosts):
        self.logger.info("📁 Starting directory discovery...")

        for host in live_hosts[:3]:  # Limit for performance
            self.logger.info(f"Directory discovery on {host}")

            output_file = f"{self.output_dir}/directories/dirsearch_{urlparse(host).netloc or 'unknown'}.txt"
            cmd = f"dirsearch -u {host} -e php,html,js,txt,xml,json --format=plain -o {output_file} --quiet"

            self.runner.run(cmd, silent=True)

    def wayback_enumeration(self):
        self.logger.info("🕰️ Enumerating URLs from Wayback Machine...")

        cmd = f"waybackurls {self.target} | head -500"
        result = self.runner.run(cmd, silent=True)

        if result:
            urls = [url.strip() for url in result.split('\n') if url.strip()]

            # Filter interesting URLs
            interesting_urls = []
            for url in urls:
                if any(ext in url.lower() for ext in ['.js', '.php', '.json', '.xml', '.txt']):
                    interesting_urls.append(url)

            wayback_file = f"{self.output_dir}/endpoints/wayback_urls.txt"
            with open(wayback_file, 'w') as f:
                for url in interesting_urls:
                    f.write(f"{url}\n")

            self.results['endpoints'].extend(interesting_urls)
            self.logger.success(f"Found {len(interesting_urls)} interesting URLs")

    def vulnerability_scanning(self, live_hosts):
        self.logger.info("🛡️ Starting vulnerability scanning...")

        if not live_hosts:
            return

        # Save live hosts to file
        hosts_file = f"{self.output_dir}/temp_hosts.txt"
        with open(hosts_file, 'w') as f:
            for host in live_hosts:
                f.write(f"{host}\n")

        # Run nuclei
        vuln_output = f"{self.output_dir}/vulnerabilities/nuclei_results.json"
        cmd = f"nuclei -l {hosts_file} -t cves,exposures,misconfiguration -severity critical,high,medium -json -o {vuln_output} -silent"

        self.runner.run(cmd, silent=True)

        # Load results
        vulnerabilities = []
        if os.path.exists(vuln_output):
            try:
                with open(vuln_output, 'r') as f:
                    for line in f:
                        if line.strip():
                            vuln = json.loads(line.strip())
                            vulnerabilities.append(vuln)
            except Exception as e:
                self.logger.error(f"Error reading vulnerabilities: {e}")

        self.results['vulnerabilities'] = vulnerabilities

        if vulnerabilities:
            self.logger.success(f"Found {len(vulnerabilities)} vulnerabilities")
        else:
            self.logger.info("No vulnerabilities found")

        # Clean up temp file
        if os.path.exists(hosts_file):
            os.remove(hosts_file)

    def generate_html_report(self):
        self.logger.info("📊 Generating HTML report...")

        # Basic HTML template
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>HyperBounty Report - {self.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #1a1a1a; color: #e0e0e0; }}
        .header {{ background: #2d3748; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
        .section {{ background: #2d3748; margin: 20px 0; padding: 20px; border-radius: 8px; }}
        .stats {{ display: flex; gap: 20px; margin: 20px 0; }}
        .stat-box {{ background: #4a5568; padding: 15px; border-radius: 8px; text-align: center; flex: 1; }}
        .vulnerability {{ margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ background: rgba(255, 0, 0, 0.2); border-left: 4px solid red; }}
        .high {{ background: rgba(255, 165, 0, 0.2); border-left: 4px solid orange; }}
        .medium {{ background: rgba(255, 255, 0, 0.2); border-left: 4px solid yellow; }}
        table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
        th, td {{ border: 1px solid #4a5568; padding: 8px; text-align: left; }}
        th {{ background: #2d3748; }}
        a {{ color: #63b3ed; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 HyperBounty Security Report</h1>
        <p>Target: <strong>{self.target}</strong></p>
        <p>Scan Date: <strong>{self.results['scan_date']}</strong></p>
    </div>

    <div class="stats">
        <div class="stat-box">
            <h3>{len(self.results['subdomains'])}</h3>
            <p>Subdomains</p>
        </div>
        <div class="stat-box">
            <h3>{len(self.results['live_hosts'])}</h3>
            <p>Live Hosts</p>
        </div>
        <div class="stat-box">
            <h3>{len(self.results['vulnerabilities'])}</h3>
            <p>Vulnerabilities</p>
        </div>
        <div class="stat-box">
            <h3>{len(self.results['open_ports'])}</h3>
            <p>Hosts with Open Ports</p>
        </div>
    </div>

    <div class="section">
        <h2>📋 Discovered Subdomains</h2>
        <table>
            <tr><th>Subdomain</th><th>Status</th></tr>
"""

        for subdomain in self.results['subdomains']:
            status = "Live" if any(subdomain in host for host in self.results['live_hosts']) else "Unknown"
            html_content += f"<tr><td>{subdomain}</td><td>{status}</td></tr>"

        html_content += """
        </table>
    </div>

    <div class="section">
        <h2>🌐 Live Hosts</h2>
        <table>
            <tr><th>URL</th><th>Technology</th><th>Server</th></tr>
"""

        for host in self.results['live_hosts']:
            tech = self.results['technologies'].get(host, {})
            cms = tech.get('cms', 'Unknown')
            server = tech.get('server', 'Unknown')
            html_content += f'<tr><td><a href="{host}" target="_blank">{host}</a></td><td>{cms}</td><td>{server}</td></tr>'

        html_content += """
        </table>
    </div>

    <div class="section">
        <h2>🛡️ Vulnerabilities</h2>
"""

        if self.results['vulnerabilities']:
            for vuln in self.results['vulnerabilities']:
                info = vuln.get('info', {})
                name = info.get('name', 'Unknown')
                severity = info.get('severity', 'unknown').lower()
                target_url = vuln.get('target', 'Unknown')

                html_content += f"""
                <div class="vulnerability {severity}">
                    <h4>{name}</h4>
                    <p><strong>Severity:</strong> {severity.upper()}</p>
                    <p><strong>Target:</strong> {target_url}</p>
                </div>
                """
        else:
            html_content += "<p>No vulnerabilities found.</p>"

        html_content += """
    </div>

    <div class="section">
        <h2>🎯 Manual Testing Recommendations</h2>
        <h3>High Priority Targets:</h3>
        <ul>
"""

        # Show high-priority targets
        priority_keywords = ['admin', 'api', 'dev', 'staging', 'test']
        for host in self.results['live_hosts']:
            if any(keyword in host.lower() for keyword in priority_keywords):
                html_content += f"<li><strong>{host}</strong> - High value target</li>"

        html_content += """
        </ul>
        <h3>Testing Checklist:</h3>
        <ul>
            <li>SQL Injection testing on input fields</li>
            <li>XSS testing in forms and parameters</li>
            <li>Directory traversal attempts</li>
            <li>File upload vulnerabilities</li>
            <li>Authentication bypass testing</li>
            <li>API endpoint security testing</li>
            <li>SSRF testing on URL parameters</li>
        </ul>
    </div>

    <footer style="text-align: center; margin-top: 50px; padding: 20px; color: #888;">
        <p>Generated by HyperBounty v2.0 | Advanced Bug Bounty Platform</p>
    </footer>
</body>
</html>
        """

        # Save HTML report
        html_file = f"{self.output_dir}/reports/security_report.html"
        with open(html_file, 'w') as f:
            f.write(html_content)

        # Save JSON report
        json_file = f"{self.output_dir}/reports/scan_results.json"
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)

        self.logger.success(f"Reports generated:")
        self.logger.info(f"  HTML: {html_file}")
        self.logger.info(f"  JSON: {json_file}")

    def run_comprehensive_scan(self, target, output_dir=None):
        # Validate target
        if not self.validate_target(target):
            self.logger.error(f"Invalid target domain: {target}")
            return False

        self.target = target
        self.output_dir = output_dir or self.create_output_directory(target)
        self.results['target'] = target

        # Display banner
        self.banner()

        try:
            # Phase 1: Subdomain Enumeration
            self.logger.info("🚀 Phase 1: Subdomain Enumeration")
            subdomains = self.subdomain_enumeration()

            if not subdomains:
                self.logger.warning("No subdomains found. Using main domain...")
                subdomains = [target]

            # Phase 2: Live Host Detection
            self.logger.info("🚀 Phase 2: Live Host Detection")
            live_hosts = self.probe_live_hosts(subdomains)

            if not live_hosts:
                self.logger.warning("No live hosts found. Using subdomains...")
                live_hosts = [f"http://{sub}" for sub in subdomains[:5]]

            # Phase 3: Port Scanning
            self.logger.info("🚀 Phase 3: Port Scanning")
            self.port_scanning(live_hosts)

            # Phase 4: Technology Detection
            self.logger.info("🚀 Phase 4: Technology Detection")
            self.technology_detection(live_hosts)

            # Phase 5: Directory Discovery
            self.logger.info("🚀 Phase 5: Directory Discovery")
            self.directory_discovery(live_hosts)

            # Phase 6: Wayback Enumeration
            self.logger.info("🚀 Phase 6: Wayback Enumeration")
            self.wayback_enumeration()

            # Phase 7: Vulnerability Scanning
            self.logger.info("🚀 Phase 7: Vulnerability Scanning")
            self.vulnerability_scanning(live_hosts)

            # Phase 8: Report Generation
            self.logger.info("🚀 Phase 8: Report Generation")
            self.generate_html_report()

            # Summary
            self.logger.success("🎉 Comprehensive scan completed!")
            self.logger.info(f"📂 Results: {self.output_dir}")
            self.logger.info(f"📊 Report: {self.output_dir}/reports/security_report.html")

            print(f"\n{Colors.CYAN}📊 SCAN SUMMARY:{Colors.END}")
            print(f"  Subdomains: {len(self.results['subdomains'])}")
            print(f"  Live Hosts: {len(self.results['live_hosts'])}")
            print(f"  Vulnerabilities: {len(self.results['vulnerabilities'])}")
            print(f"  Open Ports: {sum(len(ports) for ports in self.results['open_ports'].values())}")

            return True

        except KeyboardInterrupt:
            self.logger.warning("Scan interrupted by user")
            return False
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description="HyperBounty v2.0 - Advanced Bug Bounty Platform")
    parser.add_argument("-t", "--target", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-o", "--output", help="Output directory (default: auto-generated)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--check-tools", action="store_true", help="Check required tools")

    args = parser.parse_args()

    hyperbounty = HyperBounty(verbose=args.verbose)

    if args.check_tools:
        hyperbounty.tool_checker.check_all_tools()
        return

    # Validate target
    if not args.target:
        parser.error("Target domain is required")

    # Run scan
    success = hyperbounty.run_comprehensive_scan(args.target, args.output)

    if success:
        print(f"\n{Colors.GREEN}🎯 Happy hunting! Check your reports for findings.{Colors.END}")
    else:
        print(f"\n{Colors.RED}❌ Scan completed with errors.{Colors.END}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}👋 Scan interrupted{Colors.END}")
        sys.exit(0)
