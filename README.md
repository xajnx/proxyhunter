**SquidHunter v1**\
aaron.nelson805@gmail.com\
https://github.com/xajnx/squidhunter

Due to the website that was used to parse proxy servers for the proxyupdate script.
it was necessary to re-write a more reliable script to obtain available servers.

SquidHunter v1 is a CLI python3 script that  uses the `ip_ranges_US.txt` list of US ip-ranges to search out
Squid proxy servers. To use IP ranges for other countries visit: http://www.ipaddresslocation.org/ip_ranges/get_ranges.php and select your
country and select *CIDR* format from the drop-down menus and then download to your `squidhunter` directory.

Because this script does the searching instead of relying on other data it will take some 
time to search out open servers. It finds servers by pulling 2500 random ip-ranges from the
list and searches until it locates 25 open proxy servers. There is also an option to spoof
your MAC address if your network adapter allows for that, and requires root access and an external script.

**FEATURES**
 - scans most popular proxy ports(more can be added)
 - retrieves proxies from random ip ranges from country of choice (default:US)
 - writes results to file, easy to cut and paste into proxychains.conf
 - can scan single ip (eg:192.168.2.1) or ip range (eg: 192.168.2.0/24)

 
**FUTURE**
 - implement arguments to change vars such as `socket timeout` and single ip or ip range.
 - options to increase or decrease number of found proxies before exit
 - attempts to connect to test sites to see if proxy is valid
 - MORE!
 
**REQUIREMENTS**:\
*if you don't have any of these libraries installed, type: `pip3 install library` 
or `sudo -H pip3 install library`*

sys\
socket\
colorama\
netaddr\
time\
random\
os\
pause\
MACSpoof\
*(MACSpoof how-to can be found here: https://github.com/feross/SpoofMAC)*

**USAGE**:
**`python3 squidhunter.py`**
or to use the MACSpoof feature: **`sudo python3 squidhunter.py`**

Result:

skywalker@endor:~/scripts/python/proxyupdate$ python3 squidhunter.py\
_-=-__-=-__-=-__-=-__-=-_\
    Squid Hunter v1\
_-=-__-=-__-=-__-=-__-=-_

Would you like to spoof your MAC address?(y/n):n\
Initializing scanner..\
Please wait this may take some time.\
Initializing scanner..
Please wait this may take some time.
104.236.27.0/24: 256 available IPs
Checking host: 104.236.27.2
104.236.27.2:80 is OPEN
no proxy
Checking host: 104.236.27.6
104.236.27.6:80 is OPEN
Service: Squid
104.236.27.6:81 is OPEN
no proxy
104.236.27.6:3128 is OPEN
Service: Squid
104.236.27.6:8080 is OPEN
Service: Squid
Checking host: 104.236.27.7
104.236.27.7:80 is OPEN




