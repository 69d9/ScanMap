# ScanMap

**ScanMap** is a simple Python-based tool designed to perform network scans and check the open and closed ports on a target system. It scans commonly used ports and presents the results in a format similar to Nmap's output, without any Nmap copyrights.

## Features

- Scans a predefined list of 150 common ports (including 50 additional ports).
- Asynchronously checks open and closed ports using the `asyncio` library.
- Displays results in a clean, colored format similar to Nmap's report style.
- Works with both IP addresses and domain names (e.g., `moi.gov.krd`).

## Installation
```bash
https://github.com/69d9/ScanMap.git
cd ScanMap

## Prerequisites

Before running ScanMap, you need to install the required dependencies:

- Python 3.x
- `colorama` library for colored output

To install the necessary libraries, run the following command:

## Usage

python3 ScanMap.py
