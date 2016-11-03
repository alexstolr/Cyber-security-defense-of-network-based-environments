#!/usr/bin/python
import argparse
from scapy.all import *


def main():
    mac_set = set()
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='Open pcap file')
    args = parser.parse_args()
    pkts = rdpcap(args.file)
    for pkt in pkts:
        # Searching for outgoing messages
        if IP in pkt:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            # Messages from inside to outside
            if not (ip_dst.startswith('192.168.') or
                    ip_dst.startswith('172.16.') or
                    ip_dst.startswith('10.')):
                mac_set.add(pkt[Ether].dst)
                if pkt[Ether].dst == "d0:df:9a:c6:6e:a2":
                    pkt.show()
            # Messages from outside to inside
            if not (ip_src.startswith('192.168.') or
                    ip_src.startswith('172.16.') or
                    ip_src.startswith('10.')):
                mac_set.add(pkt[Ether].src)
        # Searching for same subnet messages
        if (DNS in pkt and pkt[DNS].qr == 0) or DHCP in pkt:
            mac_set.add(pkt[Ether].dst)
            if pkt[Ether].src == "d0:df:9a:c6:6e:a2":
                    pkt.show()
    for mac in mac_set:
        for pkt in pkts:
            # Search for the first sender in request
            if (ARP in pkt and pkt[ARP].op == 1 and
                    pkt[ARP].hwdst == "00:00:00:00:00:00" and
                    mac == pkt[Ether].src):
                print "Default Gateway was found on {} ({})".format(
                    pkt[ARP].psrc, mac)
                break


if __name__ == '__main__':
    main()
