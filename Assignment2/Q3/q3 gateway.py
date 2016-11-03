#!/usr/bin/python
import json
import os
from netfilterqueue import NetfilterQueue
from scapy.all import *
from scapy.layers.inet import IP, TCP

DF = 0x02
SYN = 0x02
RST = 0x04
ACK = 0x10
SYN_ACK = 0x12

SILENT_MODE = False
FILE_EXTENSIONS = []
MY_EXCEPTION = ''
# Dictionary of {key = (src,dst,prot,id), val = {key = frag,
# value = (payload, len, flag, seq, ack)}}
PACK_DICT = {}

SRC_PORT = 0
DST_PORT = 0
PORT_IS_SET = 0


# all have the same value for the four fields:
#  identification, source, destination, and protocol
def packet_handler(pkt):
    scapy_packet = IP(pkt.get_payload())
    global PORT_IS_SET
    if not PORT_IS_SET:
        global SRC_PORT
        global DST_PORT
        PORT_IS_SET = 1
        SRC_PORT = scapy_packet[TCP].sport
        DST_PORT = scapy_packet[TCP].dport
    # If TCP
    if scapy_packet[IP].flags == DF:
        pkt.accept()
        return
    key = (scapy_packet[IP].src, scapy_packet[IP].dst,
           scapy_packet[IP].proto, scapy_packet[IP].id)
    if IP in scapy_packet:
        # if SYN, SYN-ACK accept
        if (TCP in scapy_packet) and \
                (scapy_packet[TCP].flags == SYN or
                 scapy_packet[TCP].flags == SYN_ACK):
            pkt.accept()
            return
        # ack
        else:
            # define key for current packet
            if key not in PACK_DICT:
                if Raw in scapy_packet:
                    if TCP in scapy_packet:
                        PACK_DICT[key] = {scapy_packet[IP].frag: (
                            scapy_packet[Raw].load, scapy_packet[IP].len,
                            scapy_packet[IP].flags, scapy_packet[TCP].seq,
                            scapy_packet[TCP].ack)}
                    else:
                        PACK_DICT[key] = {scapy_packet[IP].frag: (
                            scapy_packet[Raw].load, scapy_packet[IP].len,
                            scapy_packet[IP].flags, 0, 0)}
                else:
                    if TCP in scapy_packet:
                        PACK_DICT[key] = {scapy_packet[IP].frag: (
                            '', scapy_packet[IP].len, scapy_packet[IP].flags,
                            scapy_packet[TCP].seq, scapy_packet[TCP].ack)}
                    else:
                        PACK_DICT[key] = {
                            scapy_packet[IP].frag: (
                                '', scapy_packet[IP].len,
                                scapy_packet[IP].flags,
                                0, 0)}
            else:
                if len(PACK_DICT[key]) >= 4:
                    PACK_DICT[key] = {}
                    pkt.drop()
                else:
                    if Raw in scapy_packet:
                        if TCP in scapy_packet:
                            PACK_DICT[key].update({scapy_packet[IP].frag: (
                                scapy_packet[Raw].load, scapy_packet[IP].len,
                                scapy_packet[IP].flags, scapy_packet[TCP].seq,
                                scapy_packet[TCP].ack)})
                        else:
                            PACK_DICT[key].update({scapy_packet[IP].frag: (
                                scapy_packet[Raw].load, scapy_packet[IP].len,
                                scapy_packet[IP].flags, 0, 0)})
                    else:
                        if TCP in scapy_packet:
                            PACK_DICT[key].update({scapy_packet[IP].frag: (
                                '', scapy_packet[IP].len,
                                scapy_packet[IP].flags, scapy_packet[TCP].seq,
                                scapy_packet[TCP].ack)})
                        else:
                            PACK_DICT[key].update(
                                    {scapy_packet[IP].frag: (
                                        '', scapy_packet[IP].len,
                                        scapy_packet[IP].flags, 0, 0)})
            # check if all fragments have arrived for last ack
            do_pkg(key, scapy_packet, pkt)


def do_pkg(key, scapy_packet, pkt):
    all_frags_arrived, seq, ack = check_pkg_arival(key)
    if all_frags_arrived:
        # reassamble the fragments and check for bad file extensions
        could_reasammble, asammbled_msg = reasmble(key)
        if not could_reasammble:
            if not SILENT_MODE:
                # send_error_msg(scapy_packet[IP].src)
                send_error_msg(scapy_packet, seq, ack, len(asammbled_msg))
            PACK_DICT.pop(key)
            pkt.drop()
        # reassamble succesful
        else:
            send_assambled_pkg(scapy_packet, asammbled_msg, seq, ack)
            # waiting for more fragments.
    else:
        pkt.drop()


def send_assambled_pkg(scapy_packet, payload, seq_p, ack_p):
    src_ip = scapy_packet[IP].src
    dst_ip = scapy_packet[IP].dst
    send(IP(src=src_ip, dst=dst_ip) / TCP(sport=SRC_PORT, dport=DST_PORT,
                                          flags=ACK, seq=seq_p,
                                          ack=ack_p) / payload)


def send_error_msg(scapy_packet, seq_p, ack_p, load_size):
    src_ip = scapy_packet[IP].src
    dst_ip = scapy_packet[IP].dst
    global MY_EXCEPTION
    ip_layer = IP(src=dst_ip, dst=src_ip)
    tcp_layer = TCP(sport=DST_PORT, dport=SRC_PORT, flags=ACK,
                    seq=ack_p, ack=(seq_p + load_size))
    err_pkg = ip_layer / tcp_layer / MY_EXCEPTION
    send(err_pkg)


def check_pkg_arival(key):
    length = len(PACK_DICT[key]) - 1
    sum_of_lens = 0
    seq1 = 0
    ack1 = 0
    for frag, (payload, leng, flag, seq, ack) in sorted(
            PACK_DICT[key].items()):
        sum_of_lens += leng
        if (seq != 0):
            seq1 = seq
            ack1 = ack
    total = sum_of_lens - 20 * length
    if flag == 0:
        return total == (frag * 8 + leng), seq1, ack1
    return False, seq1, ack1


def reasmble(key):
    assambled_payload = ''
    for frag, (payload, leng, flag, seq, ack) in sorted(
            PACK_DICT[key].items()):
        assambled_payload += payload
    return check_extension(assambled_payload), assambled_payload


# Check if
def check_extension(string):
    split_string = string.split('\r\n')
    if split_string[0].startswith('GET'):
        for extension in FILE_EXTENSIONS:
            extension = '.' + extension.encode('ascii', 'ignore') + ' '
            if split_string[0].find(extension) != -1:
                return False
    return True


def main():
    os.system('iptables -A FORWARD -j NFQUEUE --queue-num 1')

    # Parse setting file
    with open('settings.json') as data_file:
        data = json.load(data_file)
    global SILENT_MODE
    global FILE_EXTENSIONS
    global MY_EXCEPTION
    SILENT_MODE = data["silent_mode"]
    FILE_EXTENSIONS = data["bd_fl_ext"]
    MY_EXCEPTION = data["exception"].encode('ascii', 'ignore')

    nfqueue = NetfilterQueue()
    nfqueue.bind(1, packet_handler)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        os.system('iptables -F')
        os.system('iptables -X')


if __name__ == '__main__':
    main()
