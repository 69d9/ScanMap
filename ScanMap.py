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
import logging
import concurrent.futures
from urllib.parse import urlparse
from datetime import datetime
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor
import re

# Configure logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

# Initialize colorama for Windows support
init()

class DomainInfo:
    def __init__(self):
        self.whois_servers = {
            'com': 'whois.verisign-grs.com',
            'net': 'whois.verisign-grs.com',
            'org': 'whois.pir.org',
            'info': 'whois.afilias.net',
            'biz': 'whois.biz',
        }
        self.timeout = 10

    def get_whois_info(self, domain):
        """Get WHOIS information with multiple fallback methods."""
        try:
            # Method 1: Using python-whois
            info = whois.whois(domain)
            if info and info.registrar:
                return info
        except Exception as e:
            logger.debug(f"Primary WHOIS lookup failed: {str(e)}")

        try:
            # Method 2: Direct WHOIS server query
            tld = domain.split('.')[-1]
            if tld in self.whois_servers:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((self.whois_servers[tld], 43))
                sock.send(f"{domain}\r\n".encode())
                response = sock.recv(4096).decode()
                sock.close()
                
                # Parse the response
                info = self._parse_whois_response(response)
                if info.get('registrar'):
                    return info
        except Exception as e:
            logger.debug(f"Direct WHOIS lookup failed: {str(e)}")

        try:
            # Method 3: HTTP API fallback
            response = requests.get(
                f"https://rdap.verisign.com/com/v1/domain/{domain}",
                timeout=self.timeout
            )
            if response.status_code == 200:
                data = response.json()
                return self._parse_rdap_response(data)
        except Exception as e:
            logger.debug(f"RDAP lookup failed: {str(e)}")

        return None

    def _parse_whois_response(self, response):
        """Parse raw WHOIS response."""
        info = {}
        for line in response.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if 'registrar' in key:
                    info['registrar'] = value
                elif 'creation date' in key:
                    info['creation_date'] = value
                elif 'expiration date' in key or 'expiry date' in key:
                    info['expiration_date'] = value
        return info

    def _parse_rdap_response(self, data):
        """Parse RDAP API response."""
        info = {}
        if 'entities' in data:
            for entity in data['entities']:
                if entity.get('roles', []) == ['registrar']:
                    info['registrar'] = entity.get('vcardArray', [])[-1].get('name', None)
        if 'events' in data:
            for event in data['events']:
                if event['eventAction'] == 'registration':
                    info['creation_date'] = event['eventDate']
                elif event['eventAction'] == 'expiration':
                    info['expiration_date'] = event['eventDate']
        return info

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

        self.domain_info = DomainInfo()
        self.executor = ThreadPoolExecutor(max_workers=50)
        self.scan_timeout = 2
        self.retry_count = 3
        self.chunk_size = 100

    def is_valid_domain(self, domain):
        """Validate domain name format."""
        try:
            # Basic domain format validation
            if not domain or len(domain) > 255:
                return False
            
            # Remove trailing dot
            if domain[-1] == ".":
                domain = domain[:-1]
            
            # Check each part
            allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
            parts = domain.split(".")
            
            if len(parts) < 2:
                return False
                
            return all(allowed.match(part) for part in parts)
        except:
            return False

    def is_domain_registered(self, domain):
        """Check if domain is actually registered."""
        try:
            # Try multiple DNS resolvers
            resolvers = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222']
            
            for resolver_ip in resolvers:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [resolver_ip]
                    resolver.timeout = 3
                    resolver.lifetime = 3
                    
                    # Try to get NS records first
                    try:
                        resolver.resolve(domain, 'NS')
                        return True
                    except dns.resolver.NoAnswer:
                        # If no NS records, try A records
                        try:
                            resolver.resolve(domain, 'A')
                            return True
                        except dns.resolver.NoAnswer:
                            continue
                    except dns.resolver.NXDOMAIN:
                        continue
                    except Exception:
                        continue
                except Exception:
                    continue
            
            # If all resolvers failed, try a direct whois query
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                sock.connect(('whois.verisign-grs.com', 43))
                sock.send(f"{domain}\r\n".encode())
                response = sock.recv(4096).decode()
                sock.close()
                
                # Check for typical "No match" responses
                if "No match for" in response or "NOT FOUND" in response:
                    return False
                return True
            except:
                pass
                
            return False
        except Exception as e:
            logger.debug(f"Domain registration check failed: {str(e)}")
            return False

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
            self.target = target.lower().strip()
            
            # Validate domain format first
            if not self.is_valid_domain(self.target):
                print(f"{self.Z}[-] Invalid domain format{self.r}")
                return False
            
            # Check if domain is registered
            if not self.is_domain_registered(self.target):
                print(f"{self.Z}[-] Domain does not exist or is not registered{self.r}")
                return False
            
            # Initialize IP as unknown
            self.ip_address = "Unknown"
            
            # Try multiple DNS resolvers with timeout
            resolvers = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222']
            for resolver_ip in resolvers:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [resolver_ip]
                    resolver.timeout = 3
                    resolver.lifetime = 3
                    
                    answers = resolver.resolve(self.target, 'A')
                    if answers:
                        self.ip_address = answers[0].address
                        break
                except Exception as e:
                    logger.debug(f"DNS resolution failed for {resolver_ip}: {str(e)}")
                    continue
            
            # If all resolvers failed, try socket
            if self.ip_address == "Unknown":
                try:
                    self.ip_address = socket.gethostbyname(self.target)
                except Exception as e:
                    logger.error(f"All DNS resolution methods failed: {str(e)}")
            
            print(f"{self.A}[+] Target: {self.target} ({self.ip_address}){self.r}")
            
            # Get domain information with improved error handling
            print(f"{self.F}[+] Domain Information:{self.r}")
            whois_info = self.domain_info.get_whois_info(self.target)
            
            if whois_info:
                registrar = whois_info.get('registrar', 'Unknown')
                creation_date = whois_info.get('creation_date', 'Unknown')
                expiration_date = whois_info.get('expiration_date', 'Unknown')
                
                print(f"   Registrar: {registrar}")
                print(f"   Creation Date: {creation_date}")
                print(f"   Expiration Date: {expiration_date}")
            else:
                print(f"{self.Z}[-] Could not retrieve domain information{self.r}")

            # Get DNS records with improved error handling
            try:
                for record_type in ['A', 'MX', 'NS', 'TXT']:
                    try:
                        answers = resolver.resolve(self.target, record_type)
                        self.dns_records[record_type] = [str(rdata) for rdata in answers]
                        print(f"   {record_type} Records: {', '.join(self.dns_records[record_type])}")
                    except dns.resolver.NoAnswer:
                        continue
                    except dns.resolver.NXDOMAIN:
                        continue
                    except Exception as e:
                        logger.debug(f"Error getting {record_type} records: {str(e)}")
            except Exception as e:
                logger.debug(f"DNS record retrieval failed: {str(e)}")
            
            return True

        except Exception as e:
            logger.error(f"Target resolution failed: {str(e)}")
            print(f"{self.Z}[-] Error resolving target: {str(e)}{self.r}")
            return False

    async def check_port(self, port):
        """Check if a port is open with improved reliability."""
        for attempt in range(self.retry_count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.scan_timeout)
                result = sock.connect_ex((self.target, port))
                
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                        banner = await self.grab_banner_async(sock)
                        self.open_ports.add((port, service, banner))
                        return
                    except:
                        self.open_ports.add((port, "unknown", ""))
                        return
                sock.close()
                
                if result != 0 and attempt == self.retry_count - 1:
                    self.closed_ports.add(port)
                
            except Exception as e:
                if attempt == self.retry_count - 1:
                    logger.debug(f"Port {port} check failed: {str(e)}")
                    self.closed_ports.add(port)
            finally:
                try:
                    sock.close()
                except:
                    pass

    async def grab_banner_async(self, sock):
        """Asynchronous banner grabbing with timeout."""
        try:
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                self.executor,
                self.grab_banner,
                sock
            )
        except Exception as e:
            logger.debug(f"Banner grab failed: {str(e)}")
            return ""

    def grab_banner(self, sock):
        """Attempt to grab service banner."""
        try:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = sock.recv(1024).decode().strip()
            return banner
        except:
            return ""

    async def scan_ports(self):
        """Scan ports with improved performance and reliability."""
        try:
            all_ports = []
            for category_info in self.port_categories.values():
                all_ports.extend(category_info['ports'])
            all_ports = list(set(all_ports))  # Remove duplicates
            
            # Split ports into chunks for better management
            port_chunks = [all_ports[i:i + self.chunk_size] 
                         for i in range(0, len(all_ports), self.chunk_size)]
            
            for chunk in port_chunks:
                tasks = []
                for port in chunk:
                    tasks.append(asyncio.create_task(self.check_port(port)))
                await asyncio.gather(*tasks)
                
                # Small delay between chunks to prevent overwhelming
                await asyncio.sleep(0.1)
                
        except Exception as e:
            logger.error(f"Port scanning failed: {str(e)}")
            print(f"{self.Z}[-] Error during port scan: {str(e)}{self.r}")

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
        for port, service, banner in self.open_ports:
            try:
                if service == 'http' or port in [80, 443, 8080, 8443]:
                    await self.check_web_vulnerabilities(port)
                elif service == 'ssh' or port == 22:
                    await self.check_ssh_vulnerabilities(port)
                elif service == 'ftp' or port == 21:
                    await self.check_ftp_vulnerabilities(port)
                elif service == 'smtp' or port == 25:
                    await self.check_smtp_vulnerabilities(port)
                elif service in ['mysql', 'mariadb'] or port == 3306:
                    await self.check_mysql_vulnerabilities(port)
                elif port == 445:
                    await self.check_smb_vulnerabilities(port)
            except Exception as e:
                self.vulnerabilities.append(f"Error checking {service} on port {port}: {str(e)}")

    async def check_ssh_vulnerabilities(self, port):
        """Check SSH-specific vulnerabilities."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            if sock.connect_ex((self.target, port)) == 0:
                # Send SSH version probe
                sock.send(b"SSH-2.0-GhostScan\r\n")
                response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                # Check SSH version
                if 'SSH-1' in response:
                    self.vulnerabilities.append(f"Port {port}: Outdated SSH version 1.x detected (vulnerable)")
                
                # Check for known vulnerable versions
                vulnerable_versions = ['OpenSSH_4', 'OpenSSH_5.0', 'OpenSSH_5.1', 'OpenSSH_5.2']
                for version in vulnerable_versions:
                    if version in response:
                        self.vulnerabilities.append(f"Port {port}: Potentially vulnerable SSH version detected: {version}")
                
                # Check for weak algorithms if possible
                if 'diffie-hellman-group1' in response.lower():
                    self.vulnerabilities.append(f"Port {port}: Weak key exchange method detected")
                
            sock.close()
        except:
            pass

    async def check_ftp_vulnerabilities(self, port):
        """Check FTP-specific vulnerabilities."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            if sock.connect_ex((self.target, port)) == 0:
                # Try anonymous login
                try:
                    response = sock.recv(1024).decode()
                    sock.send(b"USER anonymous\r\n")
                    response = sock.recv(1024).decode()
                    sock.send(b"PASS anonymous@ghost.scan\r\n")
                    response = sock.recv(1024).decode()
                    
                    if '230' in response:  # 230 = Login successful
                        self.vulnerabilities.append(f"Port {port}: Anonymous FTP login allowed")
                    
                    # Check for clear-text authentication
                    if not port == 990:  # Not FTPS
                        self.vulnerabilities.append(f"Port {port}: FTP service uses clear-text authentication")
                except:
                    pass
                
            sock.close()
        except:
            pass

    async def check_smtp_vulnerabilities(self, port):
        """Check SMTP-specific vulnerabilities."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            if sock.connect_ex((self.target, port)) == 0:
                # Check for open relay
                commands = [
                    b"HELO ghost.scan\r\n",
                    b"MAIL FROM: <test@ghost.scan>\r\n",
                    b"RCPT TO: <test@ghost.scan>\r\n"
                ]
                
                try:
                    response = sock.recv(1024).decode()
                    for cmd in commands:
                        sock.send(cmd)
                        response = sock.recv(1024).decode()
                        if '250' in response:  # 250 = OK
                            self.vulnerabilities.append(f"Port {port}: SMTP server might be configured as an open relay")
                            break
                except:
                    pass
                
                # Check for VRFY command
                try:
                    sock.send(b"VRFY admin\r\n")
                    response = sock.recv(1024).decode()
                    if not response.startswith('550'):  # 550 = Command disabled
                        self.vulnerabilities.append(f"Port {port}: SMTP VRFY command enabled (information disclosure)")
                except:
                    pass
                
            sock.close()
        except:
            pass

    async def check_mysql_vulnerabilities(self, port):
        """Check MySQL-specific vulnerabilities."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            if sock.connect_ex((self.target, port)) == 0:
                # Try common username/password combinations
                common_creds = [
                    ('root', ''),
                    ('root', 'root'),
                    ('admin', 'admin')
                ]
                
                for username, password in common_creds:
                    try:
                        # This is a simplified check - in real implementation,
                        # you'd need to implement the MySQL protocol
                        if self.test_mysql_auth(sock, username, password):
                            self.vulnerabilities.append(
                                f"Port {port}: MySQL server allows login with credentials: {username}/{password}"
                            )
                            break
                    except:
                        continue
                
            sock.close()
        except:
            pass

    async def check_smb_vulnerabilities(self, port):
        """Check SMB-specific vulnerabilities."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            if sock.connect_ex((self.target, port)) == 0:
                # Check for SMBv1
                try:
                    # Send SMB negotiate protocol request
                    negotiate_request = (
                        b'\x00\x00\x00\x85'  # NetBIOS
                        b'\xff\x53\x4d\x42'  # SMB
                        b'\x72'              # Negotiate Protocol
                        b'\x00\x00\x00\x00'  # Status
                        b'\x18'              # Flags
                        b'\x53\xc8'          # Flags2
                        b'\x00\x00'          # PID High
                        b'\x00\x00\x00\x00'  # Signature
                        b'\x00\x00\x00\x00'  # Reserved
                        b'\x00\x00'          # TID
                        b'\x2f\x4b'          # PID
                        b'\x00\x00'          # UID
                        b'\xc5\x5e'          # MID
                    )
                    
                    sock.send(negotiate_request)
                    response = sock.recv(1024)
                    
                    if response[4] == 0x72:  # SMBv1 response
                        self.vulnerabilities.append(f"Port {port}: SMBv1 protocol detected (vulnerable to EternalBlue)")
                except:
                    pass
                
            sock.close()
        except:
            pass

    def test_mysql_auth(self, sock, username, password):
        """Helper method to test MySQL authentication."""
        # This is a placeholder - in real implementation,
        # you'd need to implement the MySQL authentication protocol
        return False

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
            if await self.resolve_target(target):
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
