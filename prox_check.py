#!/usr/bin/env python3
''' Proxy server checker for proxyscan.py '''

import requests

def is_prox(proxy_server):
    proxyDict = {"http": proxy_server,
                 "https": proxy_server,
                 "socks": proxy_server}

    test_site = "http://api.ipify.org/?format=json"
    headers = {'user-agent': 'Mozilla/'
                             '5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/'
                             '20091102 Firefox/'
                             '3.5.5 (.NET CLR 3.5.30729)'}

    for proxy in proxyDict:
        try:
            r = requests.get(test_site, headers=headers, proxies=proxy)
            status = r.status_code
            if status is 200:
                return(proxy)
            else:
                pass
        except Exception as e:
            pass
            

if __name__ == '__main__':
      is_prox()
