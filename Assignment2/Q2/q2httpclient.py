#! /usr/bin/env python
""" HTTP Client   - THIS IS FOR TESTING PURPOSE ONLY!!!!!! """
from scapy.all \
    import sr1, send
from hashlib import sha256
import hmac
from scapy.layers.inet import IP, TCP

PORT = 8080
DST_IP = '192.168.1.2'
SRC_IP = '192.168.1.1'
KEY = 'TOPSECRET'


def main():
    """
    :return: void()
    """
    seq = 0
    ack = 0
    # Hand Shake
    ip_layer = IP(src=SRC_IP, dst=DST_IP)
    tcp_layer = TCP(dport=PORT, seq=100, flags='S')
    syn_pkg = ip_layer / tcp_layer
    syn_ack_pkg = sr1(syn_pkg)
    if syn_ack_pkg != 0:
        ip_layer = IP(src=SRC_IP, dst=DST_IP)
        tcp_layer = TCP(dport=PORT, seq=syn_ack_pkg[TCP].ack,
                        ack=(syn_ack_pkg[TCP].seq + 1), flags='A')
        ack_pkg = ip_layer / tcp_layer
        seq = syn_ack_pkg[TCP].ack
        ack = syn_ack_pkg[TCP].seq + 1
        send(ack_pkg)
    print "Sould be connected to server by this point"
    # Finish hand-Shake
    ip_layer = IP(src=SRC_IP, dst=DST_IP)
    tcp_layer = TCP(dport=PORT, seq=seq,
                    ack=ack, flags='A')
    msg = raw_input('Enter text here: \n')
    http_msg = 'GET / HTTP/1.1\r\n' + msg + '\r\n'
    print 'http_msg: ' + str(http_msg)
    print 'src_ip: ' + str(SRC_IP)
    enc_msg = hmac.new(KEY,http_msg + SRC_IP, sha256)
    msg2 = http_msg + http_msg + enc_msg.hexdigest() + "\r\n\r\n"
    com_pkg = ip_layer / tcp_layer / msg2
    com_pkg.show()
    com_ans_pkg = sr1(com_pkg)
    com_ans_pkg.show()


if __name__ == '__main__':
    main()
