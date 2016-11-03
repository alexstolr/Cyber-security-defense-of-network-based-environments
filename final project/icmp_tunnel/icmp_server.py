#!/usr/bin/python
"""
# This is an implementation of a simple ICMP Tunnel server
# as part of a final project of 'Cyber security defense of network based
# environments' course.
# the server will receive simple data such as plain text and return answer
# to client.
# Authors: Alex Stoliar & Hen Mevashev
"""
from scapy import route
from scapy.sendrecv import sniff, send
from scapy.layers.inet import ICMP, IP
import random
import string

TUNNEL_SERVER_IP = "192.168.1.12"
TUNNEL_CLIENT_IP = "192.168.1.11"


def random_word():
    """

    :return: returns random string
    """
    length = random.randrange(1, 20, 1)
    return ''.join(random.choice(string.lowercase) for _ in range(length))


def main():
    """

    :return:  void
    """
    got_data = 0
    ip_layer = IP(src=TUNNEL_SERVER_IP, dst=TUNNEL_CLIENT_IP)
    while True:
        print "==============================================================="
        pkt = sniff(filter="icmp", timeout=15, count=1)
        print "received packet ------------------------------------------"
        pkt[0].show()
        print "received packet ------------------------------------------"
        i = 0
        tunneled_data = pkt[0][ICMP].load
        if tunneled_data[:9] == "#request:":
            i = pkt[0][ICMP].seq
            tunneled_data = "#answer: " + random_word() + str(i)
            got_data = 1
        if got_data == 0:
            tunneled_data = "Couldn't get data"
        icmp = (ICMP(type=0, code=0, id=pkt[0][ICMP].id, seq=i,
                     chksum=random.randrange(1, 65535, 1)) / tunneled_data)
        packet = ip_layer / icmp
        print "sent packet ------------------------------------------"
        packet.show()
        print "sent packet ------------------------------------------"
        send(packet)
        got_data = 0


if __name__ == '__main__':
    main()
