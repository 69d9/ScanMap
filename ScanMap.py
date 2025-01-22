import asyncio
import socket
import time
from urllib.parse import urlparse
from colorama import Fore

Z = '\033[1;31m'
X = '\033[1;33m'
Z1 = '\033[2;31m'
F = '\033[2;32m'
A = '\033[2;34m'
C = '\033[2;35m'
B = '\033[2;36m'
Y = '\033[1;34m'
r = "\033[1;31m"

print(rf"""
{Fore.YELLOW}
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
""")

target = input(f"{A}Enter target URL or IP address (without http:// or https://): {r}")

parsed_target = urlparse(target)
if parsed_target.scheme:
    target = parsed_target.netloc

try:
    ip_address = socket.gethostbyname(target)
except socket.gaierror:
    ip_address = "Unknown"

common_ports = list(set([
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443,
    445, 993, 995, 3306, 3389, 8080, 8000, 7000, 6379, 9200,
    5432, 27017, 27018, 5060, 161, 162, 8443, 3307, 3308, 11211,
    5900, 9090, 8888, 1080, 23, 5222, 5223, 587, 993, 995, 2083, 2087,
    161, 162, 631, 5000, 9999, 111, 2049, 25, 110, 8009, 119, 514, 
    631, 2049, 445, 1433, 1521, 24800, 3000, 6660, 6669, 7000, 7777,
    9000, 5000, 6000, 777, 4444, 999, 25, 139, 31337, 8080, 8181, 4444, 
    8000, 9090, 5900, 32768
]))

print(f"{A}Starting ScanMap scan on {target}...{r}")

open_ports = set()
closed_ports = set()

async def check_port(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((target, port))
        
        if result == 0:
            service = socket.getservbyport(port)
            open_ports.add((port, service))
        else:
            closed_ports.add(port)
    except:
        closed_ports.add(port)

async def scan_ports():
    tasks = []
    for port in common_ports:
        tasks.append(asyncio.create_task(check_port(port)))
    await asyncio.gather(*tasks)

try:
    start_time = time.time()
    asyncio.run(scan_ports())
    end_time = time.time()
    elapsed_time = end_time - start_time

    print(f"\n{A}Starting ScanMap scan on {target} at {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())} {r}")
    print(f"{A}Host is up ({elapsed_time:.2f} secs)")

    print(f"\n{A}Nmap scan report for {target} ({ip_address}){r}")
    print(f"{A}Host is up ({elapsed_time:.2f} secs)")

    print(f"\n{A}PORT     STATE  SERVICE{r}")
    for port, service in sorted(open_ports, key=lambda x: x[0]):
        print(f"{Y}{port}/tcp   open   {service}{r}")

    for port in sorted(closed_ports):
        print(f"{Z}{port}/tcp  closed{r}")

    print(f"\n{F}Scan completed in {elapsed_time:.2f} seconds.{r}")

except KeyboardInterrupt:
    print(f"\n{Z}Scan interrupted by user. Exiting...{r}")
    exit(0)
