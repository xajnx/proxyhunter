#!/usr/bin/env python3

''' proxyscan v1 - scan random networks for proxys '''

import time
from socket import *
from netaddr import IPNetwork
from colorama import Fore, Style
import random, os, pause, sys, re

# some pretty colors for the TERM
red = Fore.RED
blue = Fore.BLUE
green = Fore.GREEN
yellow = Fore.YELLOW
bold = Style.BRIGHT
reset = Style.RESET_ALL

# basic globals
start = time.clock()
proxy_list = []

# set environment
home = os.environ['HOME']
work = home + '/scripts/python/proxyhunter/' # Change this to reflect your working directory
pfile = work + 'proxy.lst'

# Extract available IPs from supplied network
def scan(network):
    hcount = 0
    hosts = IPNetwork(network)
    print("[{}{}{}{}]: {}{}{}{} available IPs".format(bold, blue, network, reset, bold, green, len(hosts), reset), flush=True)
    for host in map(str, hosts):
        print("Scanning: [{}{}{}{}]".format(bold, yellow, host, reset), end="\r", flush=True)
        target(host)
        hcount += 1
        sys.stdout.flush()
           
        if len(proxy_list) == 25:
            with open(pfile, 'a+') as pf:
                for proxy in proxy_list:
                    pf.write(proxy)    
            print("Proxies have been saved to {}{}\'proxy.lst\'{}".format(bold, yellow, reset))
            end = time.clock()
            elapsed = end - start
            from datetime import timedelta
            total_time = str(timedelta(hours=elapsed))
            print("Time elapsed: {}{}{}{}".format(bold, green, total_time, reset))
            print("Scanned {}{}{}{} hosts".format(bold, yellow, hcount, reset), end="\r", flush=True)
            sys.exit(0)

def target(ip):
    # scan most used proxy ports. more can be added, note: more ports = longer scan time.
    pports = [80, 81, 83, 88, 3128, 3129, 3654, 4444, 5800, 6588, 6666,
              6800, 7004, 8080, 8081, 8082, 8083, 8088, 8118, 8123, 8888,
              9000, 8084, 8085, 9999, 45454, 45554, 53281]
    # scount = 0
    for port in pports:
        # Attempt to connect to socket
        s = socket(AF_INET, SOCK_STREAM)
        # Set the timeout for connecting to the socket. Can be adjusted as necessary, but any lower will
        # drastically reduce accuracy
        s.settimeout(0.08)
        result = s.connect_ex((ip, port))
        if result == 0:
            print("", flush=True)
            print("\n{}{}{}{}:{} [{}{}OPEN{}]".format(bold, yellow, ip, reset, port, bold, green, reset), flush=True)
            # Check for SQUID service
            message = bytes("GET / HTTP/1.1\r\n\r\n", 'utf-8')
            s.sendall(message)
            # Set the timeout for connecting to test site. Can be adjusted but lower time will
            # drastically reduce accuracy
            s.settimeout(0.08)
            try:
                reply = s.recv(100)
                data = reply.decode(encoding='utf-8')
                p = re.compile("Server: (.*)/")
                service = p.search(data)
            except Exception:
                pass
            try:
                if service.group(1) == 'squid':
                    stype = service.group(1)
                    print("Service: [{}{}{}{}]".format(bold, green, str(stype).capitalize(), reset))
                    with open('proxy.lst', 'a') as f:
                        print("Saving..\n")
                        proxy_list.append("[" + stype.upper() + "] - http " + str(ip) + " " + str(port) + "\n")
                        print("{}{}Proxy Count: {}[{}{}{}{}{}]".format(bold, yellow, reset, bold, len(proxy_list), bold, yellow, reset))
                        sys.stdout.flush()
                else:
                    # Check for SOCKS services
                    try:
                        from prox_check import is_prox
                        p_str = "http://" + str(ip) + ":" + str(port)
                        prox = is_prox(p_str)
                        if prox == 'socks':
                            print("Service: [{}{}{}{}]".format(bold, green, prox.capitalize(), reset))
                            with open('proxy.lst', 'a') as f:
                                print("Saving..\n")
                                proxy_list.append("[" + prox.upper() + "] - http " + str(ip) + " " + str(port) + "\n")
                                print("{}{}Proxy Count: {}[{}{}{}{}]".format(bold, yellow, reset, bold, len(proxy_list), yellow, reset))
                                sys.stdout.flush()
                        else:
                            pass
                    except Exception as e:
                        print(str(e))     
            except (NameError, AttributeError) as e:
                print("[{}{}No Proxy{}]\nSkipping..\n".format(bold, red,  reset), flush=True)
        else:
            pass
        s.close()
        
        #print("{}Proxy Count {}{}{}".format(bold, yellow, len(proxy_list), reset))
if __name__ == '__main__':

    with open('ip_ranges_US.txt', 'r') as f:
        subnets = f.readlines()

        netlist = []
        num_ips = len(subnets)
        while len(netlist) < 30:
            rand_ip = random.randint(0, num_ips)
            try:
                netlist.append(subnets[rand_ip])
            except IndexError:
                pass

    os.system("clear")
    print("{}{}  ProxyHunter v1.1       {}".format(bold, yellow, reset))
    print("\n{}{}Initializing scanner..\nThis may take some time.\n{}".format(bold, blue, reset))
    for net in netlist:
        ip = net.lstrip().strip('\n')
        try:
            scan(ip)
        except KeyboardInterrupt:
            print("\n{}{}Exiting..{}".format(bold, red, reset))
            sys.exit(0)           
            
