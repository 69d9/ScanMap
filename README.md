# ScanMap

**ScanMap** is a simple tool built with Python aimed at performing network scans to check open and closed ports on the target system. The tool scans a set of common ports and presents the results in a well-organized and easy-to-read format.
## Features

- Scans a predefined list of 150 common ports (including 50 additional ports).
- Asynchronously checks open and closed ports using the `asyncio` library.
- Displays results in a clean, colored format similar to Nmap's report style.
- Works with both IP addresses and domain names (e.g., `example.com`).

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
