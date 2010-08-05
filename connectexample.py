#!/usr/bin/env python

import socket
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("127.0.0.1", 6666))
s.send('{"action": "stream", "parameters": {"port": 80, "nodeid": "'+sys.argv[1]+'"}}')
s.send('HELLO WORLD')
s.recv(0)
