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

start = time.clock()

def scan(network):
    hosts = IPNetwork(network)
    print("{}{}{}{}: {}{}{}{} available IPs".format(bold, blue, network, reset, bold, green, len(hosts), reset), flush=True)
    for host in map(str, hosts):
        print("Checking host: {}{}{}{}".format(bold, yellow, host, reset), end="\r", flush=True)
        target(host)
        sys.stdout.flush()

def target(ip):
    # scan most used proxy ports. more can be added, note: more ports = longer scan time.
    pports = [80, 81, 83, 88, 3128, 3129, 3654, 4444, 5800, 6588, 6666,
              6800, 7004, 8080, 8081, 8082, 8083, 8088, 8118, 8123, 8888,
              9000, 8084, 8085, 9999, 53281]
    pcount = 0
    scount = 0
    for port in pports:
        # Attempt to connect to socket
        s = socket(AF_INET, SOCK_STREAM)
        s.settimeout(0.08)
        result = s.connect_ex((ip, port))
        if result == 0:
            print("", flush=True)
            print("{}{}{}{}:{} is {}{}OPEN{}".format(bold, blue, ip, reset, port, bold, green, reset), flush=True)

            # Check for SQUID service
            message = bytes("GET / HTTP/1.1\r\n\r\n", 'utf-8')
            s.sendall(message)
            s.settimeout(0.5)
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
                    print("Service: {}{}{}{}".format(bold, green, str(stype).capitalize(), reset))
                    with open('proxy.lst', 'a') as f:
                        print("Saving..")
                        f.write("[" + stype.upper() + "] - http " + str(ip) + " " + str(port) + "\n")
                        pcount += 1
                        sys.stdout.flush()
                else:
                    try:
                        from prox_check import is_prox
                        p_str = "http://" + str(ip) + ":" + str(port)
                        prox = is_prox(p_str)
                        if prox == 'socks':
                            print("Service: {}{}{}{}".format(bold, green, prox.capitalize(), reset))
                            with open('proxy.lst', 'a') as f:
                                print("Saving..")
                                f.write("[" + prox.upper() + "] - http " + str(ip) + " " + str(port) + "\n")
                                pcount += 1
                                sys.stdout.flush()
                        else:
                            pass
                    except Exception as e:
                        print(str(e))

            except (NameError, AttributeError):
                print("{}No proxy{} - skipping..\n".format(red, reset), flush=True)
                sys.stdout.flush()
        else:
            pass
        s.close()
    scount += 1
    sys.stdout.flush()

    if scount < 25:
        pass

    elif scount == 25:
        print("Found {}{}{} available proxy servers.".format(green, pcount, reset))
        end = time.clock()
        print("Scan took approximately {}{}{}{} seconds".format(bold, blue, (round(end - start),2), reset))
        if pcount == 0:
           print("No available servers fouund. Please re-run the script to search again")
        print("Proxy servers have been saved to {}{}\'proxy.lst\'{}".format(bold, green, reset ))
        sys.exit(0)

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
    print("{}{}_-=-_{}".format(bold, yellow, reset)*5)
    print("{}{}     Squid Hunter v1       {}".format(bold, blue, reset))
    print("{}{}_-=-_{}".format(bold, yellow, reset)*5)
    need_spoof = input("\nWould you like to spoof your MAC address?(y/n):")
    if need_spoof is 'y':
        if os.geteuid() != 0 or os.path.isfile("mac-spoof.py") is False:
            exit("{} This options requires root access and the script {}mac-spoof.py{}\n"
                 "{} if you do not have the {}MacSpoof script{}{}, please install by typing:\n"
                 "{} sudo -H pip3 install MacSpoof\"{}{} and then re-run proxyscan.py as root{}\n".format(bold, red, reset, bold, red, reset, bold, red, reset, bold, reset))
        try:
            print(os.system("spoof-mac.py list"))
            net_dev = input("Please enter the {}device{} you wish to spoof: ".format(red, reset))
            print("Randomizing MAC address. Please wait..\n")
            pause.seconds(10)
            os.system("spoof-mac.py randomize " + net_dev)
            pause.seconds(15)
        except Exception as e:
            print("Unable to spoof MAC. Skipping..")

    print("\n{}{}Initializing scanner..\nPlease wait this may take some time.{}".format(bold, yellow, reset))
    for net in netlist:
        ip = net.lstrip().strip('\n')
        try:
            scan("192.223.24.0/24")
        except KeyboardInterrupt:
            print("\nExiting..")
            sys.exit(0)
