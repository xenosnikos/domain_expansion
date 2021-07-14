#!/usr/bin/env python
# coding: utf-8
# Sublist3r2 v1.0


# modules in standard library
import re
import sys
import os
import argparse
import time
import hashlib
import random
import multiprocessing
import threading
import socket
import json
from collections import Counter

# external modules
import dns.resolver
import requests
from aiodnsbrute.cli import aioDNSBrute

# Python 2.x and 3.x compatiablity
if sys.version > '3':
    import urllib.parse as urlparse
    import urllib.parse as urllib
else:
    import urlparse
    import urllib


# In case you cannot install some of the required development packages
# there's also an option to disable the SSL warning:
try:
    import requests.packages.urllib3

    requests.packages.urllib3.disable_warnings()
except:
    pass

# Check if we are running this on windows platform
is_windows = sys.platform.startswith('win')

# Console Colors
if is_windows:
    # Windows deserves coloring too :D
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'  # white
    try:
        import win_unicode_console, colorama

        win_unicode_console.enable()
        colorama.init()
        # Now the unicode will work ^_^
    except:
        print("[!] Error: Coloring libraries not installed, no coloring will be used [Check the readme]")
        G = Y = B = R = W = G = Y = B = R = W = ''


else:
    G = '\033[92m'  # green
    Y = '\033[93m'  # yellow
    B = '\033[94m'  # blue
    R = '\033[91m'  # red
    W = '\033[0m'  # white



def main(domain, threads, savefile, ports, silent, verbose, enable_bruteforce, engines):
    bruteforce_list = set()
    search_list = set()

    if is_windows:
        subdomains_queue = list()
    else:
        subdomains_queue = multiprocessing.Manager().list()

    # Check Bruteforce Status
    if enable_bruteforce or enable_bruteforce is None:
        enable_bruteforce = True

    # Validate domain
    domain_check = re.compile("^(http|https)?[a-zA-Z0-9]+([\-\.]{1}[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}$")
    if not domain_check.match(domain):
        if not silent:
            print(R + "Error: Please enter a valid domain" + W)
        return []

    if not domain.startswith('http://') or not domain.startswith('https://'):
        domain = 'http://' + domain

    parsed_domain = urlparse.urlparse(domain)

    if not silent:
        print(B + "[-] Enumerating subdomains now for %s" % parsed_domain.netloc + W)

    if verbose and not silent:
        print(Y + "[-] verbosity is enabled, will show the subdomains results in realtime" + W)

    supported_engines = {'baidu': BaiduEnum,
                         'yahoo': YahooEnum,
                         'google': GoogleEnum,
                         'bing': BingEnum,
                         'ask': AskEnum,
                         'netcraft': NetcraftEnum,
                         'dnsdumpster': DNSdumpster,
                         'virustotal': Virustotal,
                         'threatcrowd': ThreatCrowd,
                         'ssl': CrtSearch,
                         'passivedns': PassiveDNS
                         }

    chosenEnums = []

    if engines is None:
        chosenEnums = [
            BaiduEnum, YahooEnum, GoogleEnum, BingEnum, AskEnum,
            NetcraftEnum, DNSdumpster, Virustotal, ThreatCrowd,
            CrtSearch, PassiveDNS
        ]
    else:
        engines = engines.split(',')
        for engine in engines:
            if engine.lower() in supported_engines:
                chosenEnums.append(supported_engines[engine.lower()])

    # Start the engines enumeration
    enums = [enum(domain, [], q=subdomains_queue, silent=silent, verbose=verbose) for enum in chosenEnums]
    for enum in enums:
        enum.start()
    for enum in enums:
        enum.join()

    subdomains = set(subdomains_queue)
    for subdomain in subdomains:
        search_list.add(subdomain)

    if enable_bruteforce:
        if not silent:
            print(G + "[-] Starting bruteforce module now using aiodnsbrute.." + W)
        record_type = False
        path_to_file = os.path.dirname(os.path.realpath(__file__))
        subs = os.path.join(path_to_file, 'aiodnsbrute', 'subdomains-top1million-110000.txt')
        resolvers = os.path.join(path_to_file, 'aiodnsbrute', 'resolvers.txt')
        wildcard = True
        verify = True
        query = True
        thread_count = threads
        bruteforce_list = aioDNSBrute.bruteforce_domain(parsed_domain.netloc, resolvers, subs, wildcard, verify,
                                                        search_list, thread_count, query)
    subdomains = search_list.union(bruteforce_list)

    if subdomains:
        subdomains = sorted(subdomains, key=subdomain_sorting_key)

        if savefile:
            write_file(savefile, subdomains)

        if not silent:
            print(Y + "[-] Total Unique Subdomains Found: %s" % len(subdomains) + W)

        if ports:
            if not silent:
                print(G + "[-] Start port scan now for the following ports: %s%s" % (Y, ports) + W)
            ports = ports.split(',')
            pscan = portscan(subdomains, ports)
            pscan.run()

        elif not silent:
            for subdomain in subdomains:
                print(G + subdomain + W)
    return list(subdomains)