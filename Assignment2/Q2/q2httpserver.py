#!/usr/bin/python
""" HTTP Server """
import BaseHTTPServer
import hmac
from _sha256 import sha256

HOST_NAME = '192.168.1.2'
PORT_NUMBER = 8080
KEY = 'TOPSECRET'


class MyHandler(BaseHTTPServer.BaseHTTPRequestHandler):
    """ HTTP Server Handler """

    def do_HEAD(self):
        """ Handle HTTP Headers """
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_GET(self):
        """Respond to a GET request."""
        line1 = self.rfile.readline()[:-2]
        line2 = self.rfile.readline()[:-2]
        orig_hash = self.rfile.readline()[:-2]
        src_ip = self.client_address[0]
        http_msg = line1 + '\r\n' + line2 + '\r\n'
        enc_msg = hmac.new(KEY, http_msg + src_ip, sha256)
        calc_hash = enc_msg.hexdigest()
        if orig_hash == calc_hash:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                "<html><head><title>Ex1 Web Server Template</title></head>")
            self.wfile.write("<body><p>Welcome to Q1 !!!.</p>")
            self.wfile.write("</body></html>")
            print "Connectd From: " + self.client_address[0]
        else:
            # prevented ip spoofing
            self.send_response(405)


if __name__ == '__main__':
    ServerClass = BaseHTTPServer.HTTPServer
    HTTPD = ServerClass((HOST_NAME, PORT_NUMBER), MyHandler)
    print "Server Starts - %s:%s" % (HOST_NAME, PORT_NUMBER)
    try:
        HTTPD.serve_forever()
    except KeyboardInterrupt:
        pass
    HTTPD.server_close()
    print "Server Stops - %s:%s" % (HOST_NAME, PORT_NUMBER)
