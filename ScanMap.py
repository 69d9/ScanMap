#!/usr/bin/env python3

import asyncio
import socket
import time
import sys
import os
import platform
import requests
import json
import whois
import dns.resolver
import ssl
import subprocess
from urllib.parse import urlparse
from datetime import datetime
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor
import re

# Initialize colorama for Windows support
init()

class ScanMap:
    def __init__(self):
        self.Z = '\033[1;31m'
        self.X = '\033[1;33m'
        self.Z1 = '\033[2;31m'
        self.F = '\033[2;32m'
        self.A = '\033[2;34m'
        self.C = '\033[2;35m'
        self.B = '\033[2;36m'
        self.Y = '\033[1;34m'
        self.r = "\033[1;31m"
        
        self.banner = rf"""
{Fore.RED}
    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
    █▄░▄██▀▄─██░▄▄░█░▄▄▀█▄─▄█░▄▄█▄─▄▄─█▄─▄▄─█▄─▄▄▀█░▄▄░██▀▄─██▄─▄▄▀█▄─▄▄─█▄─▄▄▀█░▄▄░█
    ██░███─▀─██░▀▀░█░▀▀░██░██░▄▄██─▄█▀██─▄█▀██─▄─▄█░▀▀░██─▀─███─██─██─▄█▀██─▄─▄█░▀▀░█
    ▀▀▄▄▀▀▄▄▀▀▄▄▀▀░▀░▀▀░▀▄▄▄▀▄▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▀▀░▀▄▄▀▄▄▀▄▄▄▄▀▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▀▀░
{Fore.YELLOW}
    Advanced Port Scanner and Security Analyzer
    Coded By GhosT LulzSec
    Telegram : @WW6WW6WW6
    GitHub: https://github.com/69d9
    All rights reserved.
{Fore.CYAN}
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  [*] Features:                                                           ║
    ║      - Advanced Port Analysis         - Service Detection               ║
    ║      - Security Vulnerability Checks  - Firewall Detection             ║
    ║      - DNS Enumeration               - SSL/TLS Analysis               ║
    ║      - Real-time Banner Grabbing     - Custom Protocol Analysis      ║
    ╚══════════════════════════════════════════════════════════════════════════╝
"""
        
        self.target = None
        self.ip_address = None
        self.open_ports = set()
        self.closed_ports = set()
        self.vulnerabilities = []
        self.os_info = None
        self.whois_info = None
        self.dns_records = {}
        self.ssl_info = None
        self.firewall_status = None
        self.service_versions = {}
        
        # Extended port categories with descriptions
        self.port_categories = {
            'Critical Services': {
                'ports': [21, 22, 23, 25, 53, 80, 443, 3389],
                'description': 'Essential services that require immediate attention'
            },
            'Web Applications': {
                'ports': [80, 443, 8080, 8443, 4443, 8000, 8888, 9000, 9090],
                'description': 'Web servers and applications'
            },
            'Databases': {
                'ports': [1433, 1521, 3306, 5432, 6379, 27017, 27018, 27019],
                'description': 'Database management systems'
            },
            'Remote Management': {
                'ports': [22, 23, 3389, 5900, 5901, 5902, 5903],
                'description': 'Remote access and management services'
            },
            'File Sharing': {
                'ports': [137, 138, 139, 445, 2049],
                'description': 'File sharing and network storage'
            },
            'Email Services': {
                'ports': [25, 110, 143, 465, 587, 993, 995],
                'description': 'Email and messaging protocols'
            },
            'Security Services': {
                'ports': [161, 162, 389, 636, 1645, 1812],
                'description': 'Security and authentication services'
            },
            'Monitoring': {
                'ports': [161, 162, 199, 1098, 1099, 4949],
                'description': 'System and network monitoring'
            },
            'Development': {
                'ports': [8080, 9000, 9001, 9002, 3000, 4200, 5000],
                'description': 'Development and debugging services'
            },
            'IoT & Industrial': {
                'ports': [1883, 8883, 5683, 5684, 502, 44818],
                'description': 'IoT devices and industrial protocols'
            }
        }

        # Service fingerprints for better identification
        self.service_fingerprints = {
            'http': [b'HTTP/', b'Server:', b'nginx', b'apache', b'IIS'],
            'ssh': [b'SSH-2.0', b'SSH-1.99', b'SSH-1.5'],
            'ftp': [b'220', b'FTP', b'FileZilla'],
            'smtp': [b'220', b'SMTP', b'Postfix', b'Exchange'],
            'mysql': [b'MySQL', b'MariaDB'],
            'rdp': [b'RDP', b'RDPClient'],
            'telnet': [b'Telnet']
        }

    async def advanced_service_detection(self, port, banner):
        """Enhanced service and version detection."""
        service_info = {'service': 'unknown', 'version': 'unknown', 'product': 'unknown'}
        
        if not banner:
            return service_info

        # Custom protocol analysis
        for service, signatures in self.service_fingerprints.items():
            for sig in signatures:
                if sig.lower() in banner.lower().encode():
                    service_info['service'] = service
                    
                    # Extract version information
                    version_patterns = [
                        rb'(?i)version[ :]*([\d.]+)',
                        rb'(?i)([\d.]+)[-_]release',
                        rb'(?i)/([\d.]+)'
                    ]
                    
                    for pattern in version_patterns:
                        match = re.search(pattern, banner.encode())
                        if match:
                            service_info['version'] = match.group(1).decode()
                            break
                    
                    # Extract product information
                    product_patterns = [
                        rb'(?i)server: ([^\r\n]+)',
                        rb'(?i)product: ([^\r\n]+)'
                    ]
                    
                    for pattern in product_patterns:
                        match = re.search(pattern, banner.encode())
                        if match:
                            service_info['product'] = match.group(1).decode()
                            break
                    
                    return service_info
        
        return service_info

    def format_service_info(self, port, service_info):
        """Format service information for display."""
        service = service_info['service']
        version = service_info['version']
        product = service_info['product']
        
        if service != 'unknown':
            result = f"{port}/tcp {service}"
            if version != 'unknown':
                result += f" {version}"
            if product != 'unknown':
                result += f" ({product})"
            return result
        return f"{port}/tcp"

    async def analyze_response_time(self, port):
        """Analyze port response time and behavior."""
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            if sock.connect_ex((self.target, port)) == 0:
                response_time = time.time() - start_time
                
                # Test multiple connections
                connection_times = []
                for _ in range(3):
                    start = time.time()
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(2)
                    if test_sock.connect_ex((self.target, port)) == 0:
                        connection_times.append(time.time() - start)
                    test_sock.close()
                
                return {
                    'response_time': response_time,
                    'avg_response': sum(connection_times) / len(connection_times) if connection_times else None,
                    'stability': self.calculate_stability(connection_times)
                }
            return None
        except:
            return None

    def calculate_stability(self, times):
        """Calculate connection stability score."""
        if not times or len(times) < 2:
            return "Unknown"
        
        variance = sum((x - sum(times)/len(times)) ** 2 for x in times) / len(times)
        if variance < 0.1:
            return "Stable"
        elif variance < 0.3:
            return "Moderate"
        else:
            return "Unstable"

    async def check_security_headers(self, port):
        """Check for security headers on web services."""
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS',
            'X-Frame-Options': 'Missing clickjacking protection',
            'X-Content-Type-Options': 'Missing MIME-type protection',
            'Content-Security-Policy': 'Missing CSP',
            'X-XSS-Protection': 'Missing XSS protection',
            'Referrer-Policy': 'Missing referrer policy'
        }

        try:
            protocol = 'https' if port == 443 else 'http'
            response = requests.get(
                f"{protocol}://{self.target}:{port}",
                verify=False,
                timeout=5,
                headers={'User-Agent': 'GhostScan Security Analyzer'}
            )
            
            missing_headers = []
            for header, message in security_headers.items():
                if header not in response.headers:
                    missing_headers.append(message)
            
            return missing_headers
        except:
            return []

    def print_results(self, elapsed_time):
        """Enhanced results presentation."""
        print(f"\n{self.A}{'='*80}{self.r}")
        print(f"{self.F}[+] Scan Results for {self.target} ({self.ip_address}){self.r}")
        print(f"{self.A}{'='*80}{self.r}")

        # Print scan statistics
        print(f"\n{self.Y}[*] Scan Statistics:{self.r}")
        print(f"  - Scan Duration: {elapsed_time:.2f} seconds")
        print(f"  - Total Ports Scanned: {len(self.open_ports) + len(self.closed_ports)}")
        print(f"  - Open Ports: {len(self.open_ports)}")
        
        # Print results by category
        for category, info in self.port_categories.items():
            category_ports = [(p, s, b) for p, s, b in self.open_ports if p in info['ports']]
            if category_ports:
                print(f"\n{self.F}[+] {category}: {info['description']}{self.r}")
                for port, service, banner in sorted(category_ports):
                    service_info = self.advanced_service_detection(port, banner)
                    formatted_service = self.format_service_info(port, service_info)
                    print(f"  {self.Y}{formatted_service}{self.r}")
                    
                    # Print additional security information for web services
                    if port in [80, 443, 8080, 8443]:
                        missing_headers = self.check_security_headers(port)
                        if missing_headers:
                            print(f"    {self.Z}Security Issues:{self.r}")
                            for header in missing_headers:
                                print(f"    - {header}")

        # Print DNS information if available
        if self.dns_records:
            print(f"\n{self.F}[+] DNS Information:{self.r}")
            for record_type, records in self.dns_records.items():
                print(f"  {self.Y}{record_type} Records:{self.r}")
                for record in records:
                    print(f"    - {record}")

        # Print security analysis
        if self.vulnerabilities:
            print(f"\n{self.Z}[!] Security Concerns:{self.r}")
            for vuln in self.vulnerabilities:
                print(f"  - {vuln}")

        # Print recommendations
        print(f"\n{self.F}[+] Security Recommendations:{self.r}")
        if len(self.open_ports) > 0:
            print("  - Review and close unnecessary open ports")
            print("  - Implement proper access controls for critical services")
            print("  - Regular security audits recommended")
            
        print(f"\n{self.A}{'='*80}{self.r}")

    async def resolve_target(self, target):
        """Resolve target hostname to IP and gather basic information."""
        try:
            self.target = target
            self.ip_address = socket.gethostbyname(target)
            print(f"{self.A}[+] Target: {target} ({self.ip_address}){self.r}")
            
            # Get WHOIS information
            try:
                self.whois_info = whois.whois(target)
                print(f"{self.F}[+] Domain Information:{self.r}")
                print(f"   Registrar: {self.whois_info.registrar}")
                print(f"   Creation Date: {self.whois_info.creation_date}")
                print(f"   Expiration Date: {self.whois_info.expiration_date}")
            except:
                print(f"{self.Z}[-] WHOIS information unavailable{self.r}")

            # Get DNS records
            try:
                for record_type in ['A', 'MX', 'NS', 'TXT']:
                    answers = dns.resolver.resolve(target, record_type)
                    self.dns_records[record_type] = [str(rdata) for rdata in answers]
            except:
                pass

        except socket.gaierror:
            print(f"{self.Z}[-] Could not resolve hostname{self.r}")
            sys.exit(1)

    async def check_port(self, port):
        """Check if a port is open and gather service information."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                    banner = self.grab_banner(sock)
                    self.open_ports.add((port, service, banner))
                    
                    # Additional service checks
                    if port == 443:
                        self.check_ssl_security(self.target, port)
                except:
                    self.open_ports.add((port, "unknown", ""))
            else:
                self.closed_ports.add(port)
            sock.close()
        except:
            self.closed_ports.add(port)

    def grab_banner(self, sock):
        """Attempt to grab service banner."""
        try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode().strip()
            return banner
        except:
            return ""

    def check_ssl_security(self, host, port):
        """Check SSL/TLS security configuration."""
        try:
            context = ssl.create_default_context()
            with context.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.connect((host, port))
                self.ssl_info = {
                    'version': s.version(),
                    'cipher': s.cipher(),
                    'cert': s.getpeercert()
                }
        except:
            self.ssl_info = None

    async def detect_firewall(self):
        """Attempt to detect firewall presence."""
        try:
            # Send specially crafted packets to detect firewall behavior
            responses = []
            for port in [80, 443]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((self.target, port))
                    if result == 0:
                        # Try different HTTP methods
                        for method in ['GET', 'POST', 'OPTIONS']:
                            try:
                                sock.send(f"{method} / HTTP/1.0\r\n\r\n".encode())
                                response = sock.recv(1024)
                                responses.append(response)
                            except:
                                pass
                    sock.close()
                except:
                    pass

            # Analyze responses for firewall signatures
            firewall_signatures = {
                b'WAF': 'Web Application Firewall detected',
                b'forbidden': 'Firewall blocking detected',
                b'security': 'Security appliance detected'
            }

            for response in responses:
                for signature, message in firewall_signatures.items():
                    if signature in response.lower():
                        self.firewall_status = message
                        return

            self.firewall_status = "No firewall detected or firewall is well-configured"
        except:
            self.firewall_status = "Firewall detection failed"

    async def check_vulnerabilities(self):
        """Check for common vulnerabilities."""
        # Example vulnerability checks
        for port, service, _ in self.open_ports:
            if service == 'http' or port in [80, 443, 8080]:
                await self.check_web_vulnerabilities(port)
            elif service == 'ssh':
                await self.check_ssh_vulnerabilities(port)
            elif service == 'ftp':
                await self.check_ftp_vulnerabilities(port)

    async def check_web_vulnerabilities(self, port):
        """Check for common web vulnerabilities."""
        try:
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{self.target}:{port}"
            
            # Check for common security headers
            response = requests.get(url, verify=False, timeout=5)
            headers = response.headers
            
            if 'X-Frame-Options' not in headers:
                self.vulnerabilities.append(f"Missing X-Frame-Options header on port {port}")
            if 'X-XSS-Protection' not in headers:
                self.vulnerabilities.append(f"Missing X-XSS-Protection header on port {port}")
            if 'X-Content-Type-Options' not in headers:
                self.vulnerabilities.append(f"Missing X-Content-Type-Options header on port {port}")
            
            # Check for common vulnerabilities
            common_paths = ['/admin', '/login', '/wp-admin', '/phpmyadmin']
            for path in common_paths:
                try:
                    r = requests.get(f"{url}{path}", verify=False, timeout=2)
                    if r.status_code != 404:
                        self.vulnerabilities.append(f"Potentially sensitive path found: {path} on port {port}")
                except:
                    pass

        except:
            pass

    async def scan_ports(self):
        """Scan ports asynchronously."""
        all_ports = []
        for category_ports in self.port_categories.values():
            all_ports.extend(category_ports['ports'])
        all_ports = list(set(all_ports))  # Remove duplicates
        
        tasks = []
        for port in all_ports:
            tasks.append(asyncio.create_task(self.check_port(port)))
        await asyncio.gather(*tasks)

    async def run(self):
        """Main execution method."""
        try:
            self.print_banner()
            target = input(f"{self.A}Enter target URL or IP address (without http:// or https://): {self.r}")
            
            parsed_target = urlparse(target)
            if parsed_target.scheme:
                target = parsed_target.netloc

            print(f"\n{self.F}[+] Initializing scan...{self.r}")
            start_time = time.time()

            # Execute all scan components
            await self.resolve_target(target)
            print(f"{self.F}[+] Starting port scan...{self.r}")
            await self.scan_ports()
            print(f"{self.F}[+] Checking for vulnerabilities...{self.r}")
            await self.check_vulnerabilities()
            print(f"{self.F}[+] Detecting firewall...{self.r}")
            await self.detect_firewall()

            end_time = time.time()
            elapsed_time = end_time - start_time

            self.print_results(elapsed_time)

        except KeyboardInterrupt:
            print(f"\n{self.Z}Scan interrupted by user. Exiting...{self.r}")
            sys.exit(0)
        except Exception as e:
            print(f"\n{self.Z}An error occurred: {str(e)}{self.r}")
            sys.exit(1)

    def print_banner(self):
        print(self.banner)

if __name__ == "__main__":
    scanner = ScanMap()
    asyncio.run(scanner.run())
