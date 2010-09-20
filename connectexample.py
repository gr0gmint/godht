#!/usr/bin/env python

import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", int(sys.argv[1])))
s.send('{"action": "streamconnect", "parameters": {"port": 80, "nodeid": "' + sys.argv[3] + '"}}')
f = open(sys.argv[2], "r")
while True:
	lol = f.read()
	if not lol:
		break
	s.send(lol)
