# ScanMap Professional Edition v2.0

<div align="center">
    <img src="https://img.shields.io/badge/Version-2.0-blue.svg">
    <img src="https://img.shields.io/badge/Python-3.8+-green.svg">
    <img src="https://img.shields.io/badge/License-Proprietary-red.svg">
</div>

## Overview

ScanMap Professional Edition is an advanced port scanning and network reconnaissance tool designed for security professionals and network administrators. With its powerful features and elegant interface, it provides comprehensive network analysis capabilities in a user-friendly package.

## Key Features

- **Advanced Port Analysis**: Intelligent port scanning with service detection
- **DNS Enumeration**: Complete DNS record analysis and domain information
- **Real-time Scanning**: Live results as the scan progresses
- **Service Detection**: Accurate identification of running services
- **WHOIS Integration**: Detailed domain registration information
- **Professional UI**: Clean, intuitive command-line interface

## Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Dependencies
```bash
# Install required packages
py -m pip install python-whois colorama dnspython
```

### Quick Start
```bash
# Clone the repository
git clone https://github.com/69d9/ScanMap.git

# Navigate to the directory
cd ScanMap

# Run ScanMap Professional
python ScanMap.py
```

## Usage

1. Launch ScanMap Professional:
   ```bash
   python ScanMap.py
   ```

2. When prompted, enter your target domain or IP address:
   ```
   Enter Domain or IP Address: example.com
   ```

3. ScanMap will automatically:
   - Validate the target
   - Perform DNS resolution
   - Gather WHOIS information
   - Scan for open ports
   - Identify running services

## Output Categories

ScanMap Professional organizes results into the following categories:

- **Common Services** (HTTP, FTP, SSH, etc.)
- **Database Services** (MySQL, PostgreSQL, MongoDB, etc.)
- **Mail Services** (SMTP, POP3, IMAP, etc.)
- **Security Services** (SSL/TLS, VPN, etc.)
- **Custom Services** (Other detected services)

## Professional Features

- **Clean Interface**: Professional ASCII art banner and styled output
- **Organized Results**: Categorized and well-formatted scan results
- **Error Handling**: Graceful handling of network issues and invalid inputs
- **Progress Indicators**: Real-time scan progress and status updates

## Legal Disclaimer

ScanMap Professional Edition is proprietary software. Unauthorized copying, modification, or distribution is strictly prohibited. Use responsibly and only on networks you own or have explicit permission to test.

## License

Copyright 2025 GhosT LulzSec. All Rights Reserved.

## Contact

- Telegram: @WW6WW6WW6
- GitHub: https://github.com/69d9

## Troubleshooting

### Common Issues

1. **Module not found errors**
   ```bash
   py -m pip install -r requirements.txt
   ```

2. **Permission denied**
   - Run as administrator/root
   - Check firewall settings
   - Verify network connectivity

3. **Slow scanning**
   - Check internet connection
   - Reduce target port range
   - Verify target is accessible

## Professional Support

For professional support, feature requests, or bug reports, contact us through:
- Telegram: @WW6WW6WW6

---
<div align="center">
    <i>ScanMap Professional Edition - Advanced Network Intelligence</i>
</div>
