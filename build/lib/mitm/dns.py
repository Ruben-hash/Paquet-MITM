#!/usr/bin/python3

﻿from scapy.all import sniff, DNSQR

def dns(ip, nb):
    packets = sniff(filter="src host {} and udp port 53".format(ip), timeout=nb)
    dns_queries = [pkt[DNSQR].qname.decode() for pkt in packets if DNSQR in pkt]
    for query in dns_queries:
        print(query)

dns(input("addresse"), int(input("nb")))
