"""
ProxyHunter v1.1 - Scan random networks for proxies
"""
import time
import random
import os
import sys
import re
from socket import socket, AF_INET, SOCK_STREAM
from netaddr import IPNetwork
from colorama import Fore, Style

# Pretty colors for terminal output
red = Fore.RED
blue = Fore.BLUE
green = Fore.GREEN
yellow = Fore.YELLOW
bold = Style.BRIGHT
reset = Style.RESET_ALL

def get_work_dir():
    home = os.environ.get('HOME', os.getcwd())
    return os.path.join(home, 'scripts', 'python', 'proxyhunter')

def get_proxy_file(work_dir):
    return os.path.join(work_dir, 'proxy.lst')

def scan(network, proxy_list, pfile, start_time):
    """Scan each IP in a network for open proxy ports."""
    hosts = list(IPNetwork(network))
    print(f"[{bold}{blue}{network}{reset}]: {bold}{green}{len(hosts)}{reset} available IPs", flush=True)
    hcount = 0

    for host in map(str, hosts):
        print(f"Scanning: [{bold}{yellow}{host}{reset}]", end="\r", flush=True)
        target(host, proxy_list)
        hcount += 1

        if len(proxy_list) >= 25:
            save_proxies(proxy_list, pfile)
            print(f"Proxies have been saved to {bold}{yellow}'proxy.lst'{reset}")
            elapsed = time.perf_counter() - start_time
            print(f"Time elapsed: {bold}{green}{elapsed:.2f}s{reset}")
            print(f"Scanned {bold}{yellow}{hcount}{reset} hosts", flush=True)
            sys.exit(0)

def target(ip, proxy_list):
    """Scan proxy ports for a given IP address."""
    pports = [
        80, 81, 83, 88, 3128, 3129, 3654, 4444, 5800, 6588, 6666,
        6800, 7004, 8080, 8081, 8082, 8083, 8088, 8118, 8123, 8888,
        9000, 8084, 8085, 9999, 45454, 45554, 53281
    ]
    for port in pports:
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(0.08)
        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"\n{bold}{yellow}{ip}{reset}:{port} [{bold}{green}OPEN{reset}]", flush=True)
            try:
                s.sendall(b"GET / HTTP/1.1\r\n\r\n")
                s.settimeout(0.08)
                reply = s.recv(100)
                data = reply.decode('utf-8', errors='ignore')
                service = re.search(r"Server: (.*)/", data)
            except Exception:
                service = None

            if service and service.group(1).lower() == 'squid':
                stype = service.group(1)
                print(f"Service: [{bold}{green}{stype.capitalize()}{reset}]")
                proxy_list.append(f"[{stype.upper()}] - http {ip} {port}\n")
                print(f"{bold}{yellow}Proxy Count: [{bold}{len(proxy_list)}{yellow}]{reset}")
            else:
                try:
                    from prox_check import is_prox
                    p_str = f"http://{ip}:{port}"
                    prox = is_prox(p_str)
                    if prox == 'socks':
                        print(f"Service: [{bold}{green}{prox.capitalize()}{reset}]")
                        proxy_list.append(f"[{prox.upper()}] - http {ip} {port}\n")
                        print(f"{bold}{yellow}Proxy Count: [{bold}{len(proxy_list)}{yellow}]{reset}")
                except Exception as e:
                    print(str(e))
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
    start_time = time.perf_counter()
    proxy_list = []

    work_dir = get_work_dir()
    pfile = get_proxy_file(work_dir)

    try:
        with open('ip_ranges_US.txt', 'r') as f:
            subnets = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{red}ip_ranges_US.txt not found.{reset}")
        sys.exit(1)

    netlist = select_random_subnets(subnets, 30)

    clear_screen()
    print(f"{bold}{yellow}  ProxyHunter v1.1       {reset}")
    print(f"\n{bold}{blue}Initializing scanner..\nThis may take some time.{reset}")

    for net in netlist:
        try:
            scan(net, proxy_list, pfile, start_time)
        except KeyboardInterrupt:
            print(f"\n{bold}{red}Exiting..{reset}")
            sys.exit(0)

if __name__ == '__main__':
    main()