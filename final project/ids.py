#!/usr/bin/python
"""
This is an implementation of an IDS
as part of a final project of 'Cyber security defense of network based
environments' course.
the IDS will identify ICMP Tunneling, FTP Bounce & SYN Flood attacks.
after the identification, the IDS will notify about the attack.
note that it may give a false positive of syn flood depending on
file the analysis was run on.
Authors: Alex Stoliar & Hen Mevashev
"""
from scapy.layers.inet import ICMP, IP, TCP
import argparse
from scapy.packet import Raw

from scapy.utils import rdpcap

ICMP_PACK_DICT = {}
# found_attack = 0
# icmp_request_count = 0
# icmp_reply_count = 0
INTERVAL_SECONDS = 2
# SYN_AVERAGE, ALPHA and COUNT_OF_INTERVALS  are Calculated via analayze_syn.py
# i set them manualy for output the should match an analyze of "syn_not_flood"
# pcap file.
#  with interval 2
SYN_AVERAGE = 12.0 # MUST BE DOUBLE!!!
# (ALPHA + 1)*SYN_AVERAGE--> if i receive 3 times more than average
# syn each interval(300%) then report syn flood
ALPHA = 2 # this changes based on outp
COUNT_OF_INTERVALS = 8 #8
SYN = 0x02

SAFE = 0
IOO = 1
OFO = 2
IFO = 3
OOS = 4
IOS = 5
OFS = 6
IFS = 7

PUSH_ACK = 0x018
ATTACKERS = set()
FTP_SERVER = '172.16.1.254'


def find_ftp_bounce(packets):
    """
    :param packets:
    :return: int
    """
    for packet in packets:
        if TCP in packet and packet[TCP].flags == PUSH_ACK:
            if packet[IP].dst == FTP_SERVER:
                port_ip = packet[Raw].load.split(' ')
                # if the Raw has structure of 'PORT x,x,x,x,p,p'
                if port_ip[0] == 'PORT':
                    # ip_address = x.x.x.x
                    ip_address = '.'.join(port_ip[1].split(',')[0:4])
                    # detect if foreign address
                    if ip_address != packet[IP].src:
                        return OFO
    return SAFE


def run(pkt, syn_counter):
    """
    :param pkt: pkt
    :param syn_counter: int
    :return: int
    """
    if TCP in pkt and pkt[TCP].flags == SYN:
        syn_counter += 1
    return syn_counter


def find_syn_flood(packets):
    """
    :param packets:
    :return:  int
    """
    count_of_intervals = COUNT_OF_INTERVALS
    syn_average = SYN_AVERAGE
    time_interval_start = packets[0].time  # epoch time
    time_interval_end = time_interval_start + INTERVAL_SECONDS
    syn_counter = 0
    for pkt in packets:
        if pkt.time <= time_interval_end:
            syn_counter = run(pkt, syn_counter)
        else:
            if (ALPHA + 1) * syn_average <= syn_counter:
                return OOS
            syn_average = (syn_average * count_of_intervals + syn_counter) / (
                count_of_intervals + 1)
            count_of_intervals += 1
            syn_counter = 0
            time_interval_end += INTERVAL_SECONDS
            syn_counter = run(pkt, syn_counter)
    return SAFE


# -----------------------------------------------------------------------------
# Rules for identification:
# - unusual size of packet (set to > 84)
# - check average size of packets equals for request and reply
# - length of request and reply must be the same
# - OS: Check for linux: length = 84
# ------------------------------------------
# Differnces between linux and window in echo request/reply
# The Identifier and Sequence Number can be used by the client to match the
# reply with the request that caused the reply. In practice, most Linux systems
# use a unique identifier for every ping process, and sequence number is an
# increasing number within that process. Windows uses a fixed identifier, which
# varies between Windows versions, and a sequence number that is only reset at
# boot time.
def is_request(pkt):
    """
    :param pkt:
    :return: boolean
    """
    if pkt[ICMP].type == 8:
        return True
    else:
        return False


# add packets to icmp packet dictionary
# key = icmp packet seq field
# value = touple (request packet, reply packet)
def update_icmp_dict(pkt):
    """
    :param pkt:
    :return: void
    """
    if ICMP in pkt:
        key = pkt[ICMP].id, pkt[ICMP].seq
        # check if current packet(requst or reply) is in the dictionary
        if key not in ICMP_PACK_DICT:
            if is_request(pkt):
                ICMP_PACK_DICT[key] = (pkt, 0)
            # reply packet
            if pkt[ICMP].type == 0:
                ICMP_PACK_DICT[key] = (0, pkt)
        # current packet (requst or reply) is already in the dictionary
        else:
            (l_pkt, r_pkt) = ICMP_PACK_DICT[key]
            if l_pkt == 0:
                ICMP_PACK_DICT[key] = (pkt, r_pkt)
            if r_pkt == 0:
                ICMP_PACK_DICT[key] = (l_pkt, pkt)

# for debuging
# def print_icmp_dict():
#     for val in ICMP_PACK_DICT.itervalues():
#         (l_pkg, r_pkg) = val
#         l_pkg.show()
#         r_pkg.show()


# check not standard length of data
def test_large_data(pkg):
    """
    :param pkg: pkg
    :return: boolean
    """
    if pkg[IP].len > 84:
        pkg.show()
        return True
    else:
        return False


# returns true if length of msg and ttl is wrong for win and linux
def check_os_single_pkg(pkg):
    """
    :param pkg: pkg
    :return: boolean
    """
    win = False
    lin = False
    # check if windows echo
    if pkg[IP].len == 74 and pkg[IP].ttl == 128:
        win = True
    if pkg[IP].len == 84 and (pkg[IP].ttl == 255 or pkg[IP].ttl == 64):
        lin = True
        # if not(win or lin):
        # pkg.show()
    return not (win or lin)


def check_os(l_pkg, r_pkg):
    """
    check linux and windows.
    linux ttl == 64 or 255. windows: ttl == 128
    linux length = 84, windows = 74
    :param l_pkg: pkg
    :param r_pkg: pkg
    :return: boolean
    """
    if check_os_single_pkg(l_pkg) or check_os_single_pkg(r_pkg):
        return True


def find_icmp_tunneling():
    """
    :return: int
    """
    icmp_request_count = 0
    requests_length = 0
    icmp_reply_count = 0
    replies_length = 0
    for val in ICMP_PACK_DICT.itervalues():
        (l_pkg, r_pkg) = val
        if check_os(l_pkg, r_pkg):
            return IOO
        # check average size of packets equals for request and reply
        if l_pkg != 0:
            icmp_request_count += 1
            requests_length += l_pkg[IP].len
            if test_large_data(l_pkg):
                return IOO
        if r_pkg != 0:
            icmp_reply_count += 1
            replies_length += r_pkg[IP].len
            if test_large_data(r_pkg):
                return IOO
        if requests_length / icmp_request_count != replies_length /\
                icmp_reply_count:
            return IOO
        # length of request and reply must be the same
        if l_pkg != 0 and r_pkg != 0 and l_pkg[IP].len != r_pkg[IP].len:
            return IOO
    # Didnt find anything suspicous
    return SAFE


# ----------------------------------------------------------------------------

def report_attack(found_attack):
    """
    :param found_attack:
    :return: void
    """
    if found_attack == SAFE:
        print "You are safe!"
    if found_attack == IOO:
        print "Attack identified: icmp tunneling"
    if found_attack == OFO:
        print "Attack identified: ftp bounce"
    if found_attack == IFO:
        print "Attacks identified: icmp tunneling & ftp bounce"
    if found_attack == OOS:
        print "Attack identified: syn flood"
    if found_attack == IOS:
        print "Attacks identified: icmp tunneling & syn flood"
    if found_attack == OFS:
        print "Attacks identified: ftp bounce & syn flood"
    if found_attack == IFS:
        print "Attacks identified: icmp tunneling & ftp bounce & syn flood"


def main():
    """
    :return: void
    """
    # Parse arguments & scan each packet
    parser = argparse.ArgumentParser()
    parser.add_argument('source_file')
    args = parser.parse_args()
    found_attack = 0

    packets = rdpcap(args.source_file)
    for pkt in packets:
        update_icmp_dict(pkt)
    found_attack += find_icmp_tunneling()
    found_attack += find_syn_flood(packets)
    found_attack += find_ftp_bounce(packets)
    report_attack(found_attack)


if __name__ == '__main__':
    main()
