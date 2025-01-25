#!/usr/bin/env python3

import asyncio
import socket
import time
import sys
import whois
import dns.resolver
import logging
from datetime import datetime
from colorama import init, Fore, Style
import re

# Configure logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)

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
        self.M = '\033[1;35m'
        self.U = '\033[1;36m'
        self.W = '\033[1;37m'
        self.r = '\033[0m'

        self.banner = rf"""
{Fore.RED}
     ██████╗  ██████╗ █████╗ ███╗   ██╗███╗   ███╗ █████╗ ██████╗ 
    ██╔════╝ ██╔════╝██╔══██╗████╗  ██║████╗ ████║██╔══██╗██╔══██╗
    ╚█████╗  ██║     ███████║██╔██╗ ██║██╔████╔██║███████║██████╔╝
     ╚═══██╗ ██║     ██╔══██║██║╚██╗██║██║╚██╔╝██║██╔══██║██╔═══╝ 
    ██████╔╝ ╚██████╗██║  ██║██║ ╚████║██║ ╚═╝ ██║██║  ██║██║     
    ╚═════╝   ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
{Fore.YELLOW}
    ╔═══════════════════ Professional Edition v2.0 ═══════════════════╗
    ║                Advanced Port Scanner & Analyzer                  ║
    ║                    Coded By GhosT LulzSec                       ║
    ║                  Telegram : @WW6WW6WW6                          ║
    ║                GitHub: https://github.com/69d9                  ║
    ║                    All rights reserved.                         ║
    ╚════════════════════════════════════════════════════════════════╝
{Fore.CYAN}
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║  [*] Features:                                                           ║
    ║      - Advanced Port Analysis         - Service Detection               ║
    ║      - DNS Enumeration               - WHOIS Information              ║
    ║      - Real-time Port Scanning       - Categorized Results           ║
    ╚══════════════════════════════════════════════════════════════════════════╝
"""

        self.target = None
        self.ip_address = None
        self.open_ports = set()
        self.closed_ports = set()
        self.dns_records = {}

        # Common ports to scan
        self.port_categories = {
            'Web Services': {
                'ports': [80, 443, 8080, 8443],
                'description': 'Web servers and services'
            },
            'Mail Services': {
                'ports': [25, 110, 143, 465, 587, 993, 995],
                'description': 'Email related services'
            },
            'File Transfer': {
                'ports': [20, 21, 22, 69, 115, 139, 445],
                'description': 'File transfer and sharing services'
            },
            'Database': {
                'ports': [1433, 1521, 3306, 5432],
                'description': 'Database servers'
            },
            'Remote Access': {
                'ports': [22, 23, 3389, 5900],
                'description': 'Remote access and control services'
            }
        }

        self.scan_timeout = 2
        self.retry_count = 3

    def is_valid_domain(self, domain):
        """Validate domain name format."""
        try:
            if not domain or len(domain) > 255:
                return False
            
            if domain[-1] == ".":
                domain = domain[:-1]
            
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
            resolvers = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222']
            
            for resolver_ip in resolvers:
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.nameservers = [resolver_ip]
                    resolver.timeout = 3
                    resolver.lifetime = 3
                    
                    try:
                        resolver.resolve(domain, 'NS')
                        return True
                    except dns.resolver.NoAnswer:
                        try:
                            resolver.resolve(domain, 'A')
                            return True
                        except:
                            continue
                    except:
                        continue
                except:
                    continue
            
            return False
        except Exception as e:
            logger.debug(f"Domain registration check failed: {str(e)}")
            return False

    async def resolve_target(self, target):
        """Resolve target hostname to IP and gather basic information."""
        try:
            self.target = target.lower().strip()
            
            if not self.is_valid_domain(self.target):
                print(f"{self.Z}[-] Invalid domain format{self.r}")
                return False
            
            if not self.is_domain_registered(self.target):
                print(f"{self.Z}[-] Domain does not exist or is not registered{self.r}")
                return False
            
            self.ip_address = "Unknown"
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
                    continue
            
            if self.ip_address == "Unknown":
                try:
                    self.ip_address = socket.gethostbyname(self.target)
                except Exception as e:
                    logger.error(f"All DNS resolution methods failed: {str(e)}")
            
            print(f"{self.A}[+] Target: {self.target} ({self.ip_address}){self.r}")
            
            try:
                whois_info = whois.whois(self.target)
                print(f"{self.F}[+] Domain Information:{self.r}")
                print(f"   Registrar: {whois_info.registrar}")
                print(f"   Creation Date: {whois_info.creation_date}")
                print(f"   Expiration Date: {whois_info.expiration_date}")
            except:
                print(f"{self.Z}[-] Could not retrieve domain information{self.r}")

            try:
                for record_type in ['A', 'MX', 'NS', 'TXT']:
                    try:
                        answers = resolver.resolve(self.target, record_type)
                        self.dns_records[record_type] = [str(rdata) for rdata in answers]
                        print(f"   {record_type} Records: {', '.join(self.dns_records[record_type])}")
                    except:
                        continue
            except Exception as e:
                logger.debug(f"DNS record retrieval failed: {str(e)}")
            
            return True

        except Exception as e:
            logger.error(f"Target resolution failed: {str(e)}")
            print(f"{self.Z}[-] Error resolving target: {str(e)}{self.r}")
            return False

    async def check_port(self, port):
        """Check if a port is open."""
        for attempt in range(self.retry_count):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.scan_timeout)
                result = sock.connect_ex((self.target, port))
                
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                        self.open_ports.add((port, service))
                        return
                    except:
                        self.open_ports.add((port, "unknown"))
                        return
                
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

    async def scan_ports(self):
        """Scan ports for the target."""
        try:
            all_ports = []
            for category_info in self.port_categories.values():
                all_ports.extend(category_info['ports'])
            all_ports = list(set(all_ports))
            
            tasks = []
            for port in all_ports:
                tasks.append(asyncio.create_task(self.check_port(port)))
            await asyncio.gather(*tasks)
            
        except Exception as e:
            logger.error(f"Port scanning failed: {str(e)}")
            print(f"{self.Z}[-] Error during port scan: {str(e)}{self.r}")

    def print_results(self, elapsed_time):
        """Print scan results with professional styling."""
        print(f"\n{self.X}{'═' * 80}{self.r}")
        print(f"{self.U}[+] Scan Results for {self.target} ({self.ip_address}){self.r}")
        print(f"{self.X}{'═' * 80}{self.r}")

        if self.open_ports:
            print(f"\n{self.M}[+] Open Ports by Category:{self.r}")
            for category, info in self.port_categories.items():
                category_ports = []
                for port, service in self.open_ports:
                    if port in info['ports']:
                        category_ports.append(f"{port}/{service}")
                
                if category_ports:
                    print(f"\n{self.U}╔═══ {category} {self.r}")
                    print(f"{self.C}║ {info['description']}{self.r}")
                    for port_info in category_ports:
                        print(f"{self.U}║ {self.W}▶ Port {port_info}{self.r}")
                    print(f"{self.U}╚{'═' * 50}{self.r}")

        print(f"\n{self.M}[*] Scan Statistics:{self.r}")
        print(f"{self.W}  ▶ Scan Duration: {elapsed_time:.2f} seconds{self.r}")
        print(f"{self.W}  ▶ Total Ports Scanned: {len(self.open_ports) + len(self.closed_ports)}{self.r}")
        print(f"{self.W}  ▶ Open Ports: {len(self.open_ports)}{self.r}")
        
        print(f"\n{self.X}{'═' * 80}{self.r}")

    async def run(self, target):
        """Main execution method."""
        try:
            self.print_banner()
            print(f"{self.M}[+] Initializing scan...{self.r}")
            start_time = time.time()

            if await self.resolve_target(target):
                print(f"{self.M}[+] Starting port scan...{self.r}")
                await self.scan_ports()
                
                end_time = time.time()
                elapsed_time = end_time - start_time
                self.print_results(elapsed_time)

        except KeyboardInterrupt:
            print(f"\n{self.Z}[!] Scan interrupted by user. Exiting...{self.r}")
        except Exception as e:
            print(f"\n{self.Z}[!] An error occurred: {str(e)}{self.r}")

    def print_banner(self):
        """Print the professional banner."""
        print(self.banner)

def main():
    scanner = ScanMap()
    try:
        print(f"\n{scanner.M}[*] Enter target domain or IP (e.g., example.com): {scanner.r}", end='')
        target = input().strip()
        
        if not target:
            print(f"{scanner.Z}[!] Error: Target cannot be empty{scanner.r}")
            return

        asyncio.run(scanner.run(target))
    except KeyboardInterrupt:
        print(f"\n{scanner.Z}[!] Scanner terminated by user{scanner.r}")
    except Exception as e:
        print(f"\n{scanner.Z}[!] Error: {str(e)}{scanner.r}")

if __name__ == "__main__":
    main()
