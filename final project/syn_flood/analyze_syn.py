#!/usr/bin/python
"""
# RUN THIS FILE ON: syn_not_flood.pcap
# This is an implementation of a pcap analyzer
# as part of a final project of 'Cyber security
# defense of network based environments' course.
# this program takes a pcap file as input and returns
# the average number of syn messages per 20 seconds
# Adaptive   Threshold   Algorithm
# Authors: Alex Stoliar & Hen Mevashev
"""
from scapy.layers.inet import sniff, TCP
import argparse

SYN_COUNT_ARR = []
SYN = 0x02
INTERVAL_SECONDS = 2


def run(pkt, syn_counter):
    """

    :param pkt: packet
    :param syn_counter: counts packet with syn flag
    :return: syn_counter
    """
    if TCP in pkt and pkt[TCP].flags == SYN:
        syn_counter += 1
    return syn_counter


def compute_average():
    """

    :return: average of syn per INTERVAL_SECONDS seconds
    """
    sum_of_syns = 0
    for i in range(0, len(SYN_COUNT_ARR) - 1):
        sum_of_syns += SYN_COUNT_ARR[i]
    return sum_of_syns / len(SYN_COUNT_ARR) - 1


def main():
    """

    :return: void
    """
    # Parse arguments & scan each packet
    parser = argparse.ArgumentParser()
    parser.add_argument('source_file', help='Open pcap file')
    args = parser.parse_args()
    packets = sniff(offline=args.source_file)
    time_interval_start = packets[0].time  # epoch time
    time_interval_end = time_interval_start + INTERVAL_SECONDS
    syn_counter = 0
    for pkt in packets:
        if pkt.time <= time_interval_end:
            syn_counter = run(pkt, syn_counter)
        else:
            SYN_COUNT_ARR.append(syn_counter)
            syn_counter = 0
            time_interval_end += INTERVAL_SECONDS
            syn_counter = run(pkt, syn_counter)
    #print SYN_COUNT_ARR
    print "SYN_AVERAGE: " + str(compute_average())
    print "INTERVAL_SECONDS: " + str(INTERVAL_SECONDS)
    print "COUNT_OF_INTERVALS: " + str(len(SYN_COUNT_ARR)-1)


if __name__ == '__main__':
    main()
