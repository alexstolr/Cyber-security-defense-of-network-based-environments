#!/usr/bin/python
"""
FTP Server
"""
import os
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer


def main():
    """
    :return: void
    """
    # Instantiate a dummy authorizer for managing 'virtual' users
    authorizer = DummyAuthorizer()

    # anonymous user
    authorizer.add_anonymous(os.getcwd())

    # Instantiate FTP handler class
    handler = FTPHandler
    handler.permit_foreign_addresses = True
    handler.authorizer = authorizer

    # Define a customized banner (string returned when client connects)
    handler.banner = "Service ready for new user."

    # Instantiate FTP server class and listen on 0.0.0.0:21
    address = ('', 21)
    server = FTPServer(address, handler)

    # start ftp server
    server.serve_forever()


if __name__ == '__main__':
    main()
