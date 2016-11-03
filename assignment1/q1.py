#! /usr/bin/env python

import argparse
from scapy.all import *


# print msg_set
def print_func(msg_set):
    for strings in msg_set:
        print strings


def parse_data(pkts, msg_set):
    for pkt in pkts:
        if IP in pkt:
            if 64 < pkt[IP].ttl < 128:
                output = "IP (TTL), " + pkt[IP].src + ", Windows"
                msg_set.add(output)
            elif pkt[IP].ttl <= 64:
                output = "IP (TTL), " + pkt[IP].src + ", Linux"
                msg_set.add(output)
        if TCP in pkt:
            if pkt[TCP].window == 8192:
                output = "TCP (Window Size), " + pkt[IP].src + ", Windows"
                msg_set.add(output)
            if 'Timestamp' in ''.join(x[0] for x in pkt[TCP].options):
                output = "TCP (Options), " + pkt[IP].src + ", Linux"
                msg_set.add(output)
        if Raw in pkt:
            data_str = str(pkt[Raw])
            if data_str.startswith('GET'):
                split_data = data_str.split('\n')
                for line in split_data:
                    if line.startswith('User-Agent'):
                        output = "HTTP (User-Agent), " + pkt[IP].src + ', '
                        split_line = line.split(' ')
                        if split_line[2] == "(Windows":
                            output += "Windows 10 x64"
                        if split_line[3] == "Ubuntu;":
                            output = output + split_line[3][:-1] + ' ' +\
                                     split_line[4] + ' ' + split_line[5][:-1]
                        if split_line[3] == "Linux":
                            output = output + split_line[3] + ' ' +\
                                     split_line[4][:-1]
                        for i in xrange(1, len(split_line)):
                            if split_line[i].startswith('Chrom') or \
                               split_line[i].startswith('Firef'):
                                output += ', ' + split_line[i]
                        msg_set.add(output)


def main():
    msg_set = set()
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help='Open pcap file')
    parser.add_argument('-s', '--sniff', help='Live sniff of packets',
                        action='store_true')
    args = parser.parse_args()
    if args.file:
        packets = rdpcap(args.file)
        parse_data(packets, msg_set)
        print_func(msg_set)
    elif args.sniff:
        packets = sniff(count=0)
        parse_data(packets, msg_set)
        print_func(msg_set)

if __name__ == '__main__':
    main()
