#!/usr/bin/env python

import socket
import sys
import json

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", int(sys.argv[1])))
s.send('{"action": "streamaccept", "parameters": {"port": 80}}')
j = s.recv(1000)
print j
j = json.loads(j)
print "Incoming request from "+j["nodeid"]
while True:
    lol = s.recv(1000)
    if not lol:
	    break
    print lol
