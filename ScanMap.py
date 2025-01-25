#!/usr/bin/env python3

import asyncio
import socket
import time
import sys
import os
import platform
import requests
import json
import nmap
import whois
import dns.resolver
import ssl
import subprocess
from urllib.parse import urlparse
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor

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
{Fore.YELLOW}
    ░██████╗░██╗░░██╗░█████╗░░██████╗████████╗  ░██████╗░█████╗░░█████╗░███╗░░██╗
    ██╔════╝░██║░░██║██╔══██╗██╔════╝╚══██╔══╝  ██╔════╝██╔══██╗██╔══██╗████╗░██║
    ██║░░██╗░███████║██║░░██║╚█████╗░░░░██║░░░  ╚█████╗░██║░░╚═╝███████║██╔██╗██║
    ██║░░╚██╗██╔══██║██║░░██║░╚═══██╗░░░██║░░░  ░╚═══██╗██║░░██╗██╔══██║██║╚████║
    ╚██████╔╝██║░░██║╚█████╔╝██████╔╝░░░██║░░░  ██████╔╝╚█████╔╝██║░░██║██║░╚███║
    ░╚═════╝░╚═╝░░╚═╝░╚════╝░╚═════╝░░░░╚═╝░░░  ╚═════╝░░╚════╝░╚═╝░░╚═╝╚═╝░░╚══╝
    
    Coded By GhosT LulzSec
    Telegram : @WW6WW6WW6
    GitHub: https://github.com/69d9
    All rights reserved.

            o  o   o  o
         |\/ \^/ \/|  
         |,-------.|  
       ,-.(|)   (|),-. 
       \_*._ ' '_.* _/  
        /-.--' .-`\  
   ,--./    `---'    \,--. 
   \   |(  )     (  )|   /  
hjw \  |         |  /  
`97  \ | /|\     /|\ | /  
     /  \-._     _,-/  \  
    //| \  `---'  // |\\  
   /,-.,-.\       /,-.,-.\  
  o   o   o      o   o    o  
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
        
        # Extended port list with service categories
        self.port_categories = {
            'Web Services': [80, 443, 8080, 8443, 8000, 8888],
            'Database': [3306, 5432, 27017, 1433, 1521, 6379],
            'Remote Access': [22, 23, 3389, 5900],
            'File Transfer': [21, 69, 115, 139, 445],
            'Mail': [25, 110, 143, 465, 587, 993, 995],
            'DNS': [53, 853],
            'Monitoring': [161, 162, 199, 1098, 1099],
            'VoIP': [5060, 5061],
            'Gaming': [27015, 27016, 28015],
            'IoT': [1883, 8883, 5683]
        }

    def print_banner(self):
        print(self.banner)

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
            all_ports.extend(category_ports)
        all_ports = list(set(all_ports))  # Remove duplicates
        
        tasks = []
        for port in all_ports:
            tasks.append(asyncio.create_task(self.check_port(port)))
        await asyncio.gather(*tasks)

    def print_results(self, elapsed_time):
        """Print scan results in a formatted way."""
        print(f"\n{self.A}═══════════════════════════════════════════════════════════════{self.r}")
        print(f"{self.A}Scan Results for {self.target} ({self.ip_address}){self.r}")
        print(f"{self.A}═══════════════════════════════════════════════════════════════{self.r}")
        
        # Print open ports by category
        print(f"\n{self.F}Open Ports by Category:{self.r}")
        for category, ports in self.port_categories.items():
            category_ports = [(p, s, b) for p, s, b in self.open_ports if p in ports]
            if category_ports:
                print(f"\n{self.Y}{category}:{self.r}")
                for port, service, banner in category_ports:
                    print(f"{self.F}{port}/tcp\t{service}\t{banner[:50] if banner else ''}{self.r}")

        # Print DNS information
        if self.dns_records:
            print(f"\n{self.F}DNS Records:{self.r}")
            for record_type, records in self.dns_records.items():
                print(f"{self.Y}{record_type} Records:{self.r}")
                for record in records:
                    print(f"  {record}")

        # Print SSL information
        if self.ssl_info:
            print(f"\n{self.F}SSL/TLS Information:{self.r}")
            print(f"Version: {self.ssl_info['version']}")
            print(f"Cipher: {self.ssl_info['cipher']}")

        # Print firewall status
        if self.firewall_status:
            print(f"\n{self.F}Firewall Detection:{self.r}")
            print(f"{self.firewall_status}")

        # Print vulnerabilities
        if self.vulnerabilities:
            print(f"\n{self.Z}Potential Vulnerabilities:{self.r}")
            for vuln in self.vulnerabilities:
                print(f"- {vuln}")

        print(f"\n{self.F}Scan completed in {elapsed_time:.2f} seconds.{self.r}")
        print(f"{self.A}═══════════════════════════════════════════════════════════════{self.r}")

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

if __name__ == "__main__":
    scanner = ScanMap()
    asyncio.run(scanner.run())
