#!/usr/bin/python
"""
# This is an implementation of a simple ICMP Tunnel client
# as part of a final project of 'Cyber security defense of network
# based environments' course.
# the tunnel will transfer simple data such as plain text
# Authors: Alex Stoliar & Hen Mevashev
"""
from scapy import route
from scapy.layers.inet import ICMP, IP
from scapy.sendrecv import sniff, send
import random
import string
import time

TUNNEL_SERVER_IP = "192.168.1.12"
TUNNEL_CLIENT_IP = "192.168.1.11"  # The ip of current virtual machine
# SPOOFED_SRC = "1.2.3.4"
REQUEST = "#request: "
MSG = "i have established a tunnel. here is some important data: "


def random_word():
    """

    :return: random string
    """
    length = random.randrange(1, 20, 1)
    return ''.join(
            random.choice(string.lowercase) for _ in range(length))


# Build and send ICMP message
def send_pkt(i, id_icmp):
    """

    :param i: index of message
    :param id_icmp: if of icmp message
    :return: void
    """
    tunneled_data = REQUEST + MSG + random_word()
    # fake checksum so that os will throw the packet on other side
    checksum = random.randrange(1, 65535, 1)
    # src address is known by server
    ip_layer = IP(src=TUNNEL_CLIENT_IP, dst=TUNNEL_SERVER_IP,
            chksum=checksum)
    icmp = (ICMP(type=8, code=0, seq=i, id=id_icmp) / tunneled_data)
    packet = ip_layer / icmp
    print "sent packet: "
    packet.show()
    send(packet)


def get_pkt_ans():
    """

    :return: void
    """
    got_pkt = 0
    while not got_pkt:
        pkt = sniff(filter="icmp", timeout=15, count=1)
        tunneled_data = pkt[0][ICMP].load
        if tunneled_data[:8] == "#answer:":
            got_pkt = 1
            print "received answer from tunnel server"
            print tunneled_data[9:]


def main():
    """

    :return: void
    """
    id_icmp = random.randrange(1, 65535, 1)

    i = 1
    while True:
        send_pkt(i, id_icmp)
        # print "====================================="
        get_pkt_ans()
        i += 1
        time.sleep(2)


if __name__ == '__main__':
    main()
