#! /usr/bin/env python
import socket
import sys

soc = socket.socket()
defaultIP = sys.argv[1]
defaultPort = int(sys.argv[2])
soc.connect((defaultIP, defaultPort))
print 'connected to ' + defaultIP

mGet = "GET / HTTP/1.1\r\n"
mHost = "Host: ##############.net\r\n"
mUafk = "User-Agent: Opera/12.02 (Android 4.1; Linux; Opera\
 Mobi/ADR-1111101157; U; en-US) Presto/2.9.201Version/12.02\r\n"
mUarl = "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64;\
 rv:42.0) Gecko/20100101 Firefox/42.0\r\n"
mAcc1 = "Accept: text/html,application/xhtml+xml,application/\
xml;q=0.9,*/*;q=0.8\r\n"
mAcc2 = "Accept-Language: en-US,en;q=0.5\r\n"
mAcc3 = "Accept-Encoding: gzip, deflate\r\n"
mCon = "Connection: keep-alive\r\n"
mLast = "\r\n"

httpGetMsg = mGet + mHost + mUafk + mAcc1 + mAcc2 + mAcc3 + mCon + mLast

print "message sent" if soc.send(httpGetMsg) else 0
buf = soc.recv(2048)
print buf
soc.close()
