"""
ProxyHunter v1.1 - Scan random networks for proxies
"""
import time
import random
import os
import sys
import re
import argparse
from socket import socket, AF_INET, SOCK_STREAM

try:
    from netaddr import IPNetwork
except ImportError:
    IPNetwork = None

try:
    from colorama import Fore, Style
except ImportError:
    class _NoColor:
        RED = ''
        BLUE = ''
        GREEN = ''
        YELLOW = ''

    class _NoStyle:
        BRIGHT = ''
        RESET_ALL = ''

    Fore = _NoColor()
    Style = _NoStyle()

try:
    from prox_check import is_prox
except ImportError:
    is_prox = None

# Pretty colors for terminal output
red = Fore.RED
blue = Fore.BLUE
green = Fore.GREEN
yellow = Fore.YELLOW
bold = Style.BRIGHT
reset = Style.RESET_ALL

TARGET_PROXY_COUNT = 25
SUBNET_SAMPLE_COUNT = 30
PROXY_PORTS = [
    80, 81, 83, 88, 3128, 3129, 3654, 4444, 5800, 6588, 6666,
    6800, 7004, 8080, 8081, 8082, 8083, 8088, 8118, 8123, 8888,
    9000, 8084, 8085, 9999, 45454, 45554, 53281
]

def get_work_dir():
    return os.path.dirname(os.path.abspath(__file__))

def get_proxy_file(work_dir):
    return os.path.join(work_dir, 'proxy.lst')

def parse_args():
    parser = argparse.ArgumentParser(
        description='Scan random CIDR ranges for open proxy services.'
    )
    parser.add_argument(
        '--target-count',
        type=int,
        default=TARGET_PROXY_COUNT,
        help=f'Number of proxies to find before exiting (default: {TARGET_PROXY_COUNT}).'
    )
    parser.add_argument(
        '--timeout',
        type=float,
        default=0.08,
        help='Socket timeout in seconds for port checks (default: 0.08).'
    )
    parser.add_argument(
        '--subnet-sample',
        type=int,
        default=SUBNET_SAMPLE_COUNT,
        help=f'Number of random subnets to scan (default: {SUBNET_SAMPLE_COUNT}).'
    )
    parser.add_argument(
        '--output',
        type=str,
        default='proxy.lst',
        help='Output file for discovered proxies (default: proxy.lst).'
    )
    parser.add_argument(
        '--ranges-file',
        type=str,
        default='ip_ranges_US.txt',
        help='CIDR ranges file to load (default: ip_ranges_US.txt).'
    )
    parser.add_argument(
        '--seed',
        type=int,
        default=None,
        help='Random seed for deterministic subnet selection (default: random).'
    )
    return parser.parse_args()

def scan(network, proxy_list, pfile, start_time, target_count, timeout):
    """Scan each IP in a network for open proxy ports."""
    hosts = IPNetwork(network)
    print(f"[{bold}{blue}{network}{reset}]: {bold}{green}{hosts.size}{reset} available IPs", flush=True)
    hcount = 0

    for host in map(str, hosts.iter_hosts()):
        print(f"Scanning: [{bold}{yellow}{host}{reset}]", end="\r", flush=True)
        target(host, proxy_list, timeout)
        hcount += 1

        if len(proxy_list) >= target_count:
            save_proxies(proxy_list, pfile)
            print(f"Proxies have been saved to {bold}{yellow}{pfile}{reset}")
            elapsed = time.perf_counter() - start_time
            print(f"Time elapsed: {bold}{green}{elapsed:.2f}s{reset}")
            print(f"Scanned {bold}{yellow}{hcount}{reset} hosts", flush=True)
            sys.exit(0)

def target(ip, proxy_list, timeout):
    """Scan proxy ports for a given IP address."""
    for port in PROXY_PORTS:
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(timeout)
        try:
            result = s.connect_ex((ip, port))
            if result != 0:
                continue

            print(f"\n{bold}{yellow}{ip}{reset}:{port} [{bold}{green}OPEN{reset}]", flush=True)
            service = None
            try:
                s.sendall(b"GET / HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n")
                reply = s.recv(150)
                data = reply.decode('utf-8', errors='ignore')
                service = re.search(r"Server:\s*([^\r\n/]+)", data, re.IGNORECASE)
            except OSError:
                service = None

            if service and service.group(1).strip().lower() == 'squid':
                stype = 'squid'
                entry = f"[{stype.upper()}] - http {ip} {port}\n"
                if entry not in proxy_list:
                    print(f"Service: [{bold}{green}{stype.capitalize()}{reset}]")
                    proxy_list.append(entry)
                    print(f"{bold}{yellow}Proxy Count: [{bold}{len(proxy_list)}{yellow}]{reset}")
                continue

            p_str = f"http://{ip}:{port}"
            prox = is_prox(p_str)
            if prox in ('http', 'https', 'socks5'):
                entry = f"[{prox.upper()}] - http {ip} {port}\n"
                if entry not in proxy_list:
                    print(f"Service: [{bold}{green}{prox.upper()}{reset}]")
                    proxy_list.append(entry)
                    print(f"{bold}{yellow}Proxy Count: [{bold}{len(proxy_list)}{yellow}]{reset}")
        finally:
            s.close()

def save_proxies(proxy_list, pfile):
    """Save proxies to file."""
    with open(pfile, 'a+') as pf:
        pf.writelines(proxy_list)
    proxy_list.clear()

def select_random_subnets(subnets, count=30):
    """Select a set of random, unique subnets from the list."""
    return random.sample(subnets, min(count, len(subnets)))

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def main():
    args = parse_args()
    if args.target_count < 1:
        print(f"{red}--target-count must be at least 1.{reset}")
        sys.exit(1)
    if args.subnet_sample < 1:
        print(f"{red}--subnet-sample must be at least 1.{reset}")
        sys.exit(1)
    if args.timeout <= 0:
        print(f"{red}--timeout must be greater than 0.{reset}")
        sys.exit(1)
    if IPNetwork is None:
        print(f"{red}Missing dependency: netaddr{reset}")
        print("Install with: pip3 install netaddr")
        sys.exit(1)
    if is_prox is None:
        print(f"{red}Missing dependency: requests (required by prox_check.py){reset}")
        print("Install with: pip3 install requests pysocks")
        sys.exit(1)

    start_time = time.perf_counter()
    proxy_list = []

    if args.seed is not None:
        random.seed(args.seed)

    work_dir = get_work_dir()
    pfile = args.output if os.path.isabs(args.output) else os.path.join(work_dir, args.output)
    ranges_file = args.ranges_file if os.path.isabs(args.ranges_file) else os.path.join(work_dir, args.ranges_file)

    try:
        with open(ranges_file, 'r') as f:
            subnets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{red}Ranges file not found: {ranges_file}{reset}")
        sys.exit(1)

    netlist = select_random_subnets(subnets, args.subnet_sample)

    clear_screen()
    print(f"{bold}{yellow}  ProxyHunter v1.1       {reset}")
    print(f"\n{bold}{blue}Initializing scanner..\nThis may take some time.{reset}")

    for net in netlist:
        try:
            scan(net, proxy_list, pfile, start_time, args.target_count, args.timeout)
        except KeyboardInterrupt:
            print(f"\n{bold}{red}Exiting..{reset}")
            sys.exit(0)

if __name__ == '__main__':
    main()