# ProxyHunter

Author: Aaron Nelson  
Contact: aaron.nelson805@gmail.com  
Original project: https://github.com/xajnx/proxyhunter

ProxyHunter is a Python CLI tool that scans random CIDR blocks for open proxy services on common ports and saves working results to a list file.

## Overview

This project was created as a direct scanner instead of relying on third-party proxy list sources.
It reads networks from [ip_ranges_US.txt](ip_ranges_US.txt), samples a subset, and scans hosts for open proxy ports.

Current workflow:

1. Load CIDR ranges from [ip_ranges_US.txt](ip_ranges_US.txt).
2. Randomly select a set of subnets.
3. Probe common proxy ports per host.
4. Detect proxy protocol (HTTP/HTTPS/SOCKS5) when possible.
5. Save found proxies into [proxy.lst](proxy.lst).

## Features

- Scans common proxy ports (editable in code).
- Random subnet sampling from a country IP range file.
- Detects and records proxy types.
- Writes results to [proxy.lst](proxy.lst) for reuse.

## Requirements

Python 3.8+ is recommended.

Install dependencies:

```bash
pip3 install -r requirements.txt
```

Notes:

- `sys`, `os`, `time`, `random`, `re`, and `socket` are part of the Python standard library.
- SOCKS checks in `requests` require `pysocks`.

## Installation

```bash
git clone https://github.com/xajnx/proxyhunter.git
cd proxyhunter
pip3 install -r requirements.txt
```

## Usage

Run from the project directory:

```bash
python3 proxyhunter.py
```

Output is appended to [proxy.lst](proxy.lst).

Optional flags:

- `--target-count N` stop after finding N proxies.
- `--timeout SECONDS` set socket timeout for port checks.
- `--subnet-sample N` choose how many random CIDR ranges to scan.
- `--output FILE` write results to a custom output file.
- `--ranges-file FILE` load CIDR ranges from a custom file.
- `--seed N` set RNG seed for reproducible subnet selection.

Examples:

```bash
# Find 50 proxies and save to a custom file
python3 proxyhunter.py --target-count 50 --output proxy_50.lst

# Increase timeout for slower networks
python3 proxyhunter.py --timeout 0.2

# Scan fewer subnets for a faster test run
python3 proxyhunter.py --subnet-sample 10

# Use a different country ranges file
python3 proxyhunter.py --ranges-file ip_ranges_CA.txt

# Reproduce the same random subnet sample for testing
python3 proxyhunter.py --subnet-sample 10 --seed 42
```

### Using Other Countries

To scan ranges for another country, pass a different ranges file with `--ranges-file`.

```bash
python3 proxyhunter.py --ranges-file ip_ranges_CA.txt
```

You can still replace [ip_ranges_US.txt](ip_ranges_US.txt) directly if you prefer.
One source is: http://www.ipaddresslocation.org/ip_ranges/get_ranges.php

## Important Notes

- Scan only networks and systems you are authorized to test.
- Large range files can take significant time to process.
- Some detected open ports are not usable proxies; follow-up validation is still useful.

## Proof of Concept (Original Terminal Snippet)

The original demonstration output is kept here as requested:

```text
skywalker@endor:~/scripts/python/proxyhunter$ python3 proxyhunter.py
_-=-__-=-__-=-__-=-__-=-_
    Proxy Hunter v1
_-=-__-=-__-=-__-=-__-=-_

Would you like to spoof your MAC address?(y/n):n

Initializing scanner..
Please wait this may take some time.
104.236.27.0/24: 256 available IPs
Checking host: 104.236.27.2
104.236.27.2:80 is OPEN
no proxy
Checking host: 104.236.27.6
104.236.27.6:80 is OPEN
Service: Socks
Saving..
104.236.27.6:81 is OPEN
no proxy
104.236.27.6:3128 is OPEN
Service: Socks
Saving..
104.236.27.6:8080 is OPEN
Service: Squid
Saving..
Checking host: 104.236.27.7
104.236.27.7:80 is OPEN
....
```

## Support

If this project is useful to you and you want to support development:

- CashApp: $therealajnelson


