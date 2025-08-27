#!/usr/bin/env python3
"""Proxy server checker for proxyscan.py"""

import requests

def is_prox(proxy_server):
    """
    Check if the given proxy server works for HTTP, HTTPS, or SOCKS5.

    Args:
        proxy_server (str): Proxy address, e.g. 'http://1.2.3.4:8080' or 'socks5://1.2.3.4:1080'

    Returns:
        str: The proxy type that works ('http', 'https', 'socks5'), or None if none work.
    """
    proxy_types = {
        "http": proxy_server,
        "https": proxy_server,
        "socks5": proxy_server  # requests supports 'socks5' with 'requests[socks]'
    }

    test_site = "http://api.ipify.org/?format=json"
    headers = {
        'User-Agent': ('Mozilla/5.0 (Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/'
                       '20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)')
    }

    for proxy_type, proxy_addr in proxy_types.items():
        proxies = {proxy_type: proxy_addr}
        try:
            r = requests.get(test_site, headers=headers, proxies=proxies, timeout=3)
            if r.status_code == 200:
                return proxy_type
        except Exception as e:
            # Uncomment for debugging:
            # print(f"Proxy type {proxy_type} failed: {e}")
            continue
    return None

if __name__ == '__main__':
    # Example usage; replace with actual address or CLI argument
    test_proxy = "http://1.2.3.4:8080"
    working_type = is_prox(test_proxy)
    if working_type:
        print(f"Proxy works for: {working_type}")
    else:
        print("No working proxy type found.")