#!/usr/bin/env python3
"""
network_topology_l3.py
Topologie L3 pour CDSI 2025
- s1: subnet 10.0.1.0/24  (h1,h2,h3: serveur + generators)
- s2: subnet 10.0.2.0/24  (h4,h5,h6: clients + attacker)
- r1: linux host-routeur (r1-eth0 -> s1, r1-eth1 -> s2)
- switches sont OpenFlow et contrôlés par POX distant
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI
import time

class L3Topo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Subnet A (10.0.1.0/24)
        h1 = self.addHost('h1', ip='10.0.1.10/24', mac='00:00:00:00:01:01')  # web server
        h2 = self.addHost('h2', ip='10.0.1.20/24', mac='00:00:00:00:01:02')
        h3 = self.addHost('h3', ip='10.0.1.30/24', mac='00:00:00:00:01:03')

        # Subnet B (10.0.2.0/24)
        h4 = self.addHost('h4', ip='10.0.2.40/24', mac='00:00:00:00:02:01')
        h5 = self.addHost('h5', ip='10.0.2.50/24', mac='00:00:00:00:02:02')
        h6 = self.addHost('h6', ip='10.0.2.60/24', mac='00:00:00:00:02:03')  # attacker

        # router host (r1) with two interfaces
        r1 = self.addHost('r1')  # we'll configure IPs later

        # links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

        self.addLink(h4, s2)
        self.addLink(h5, s2)
        self.addLink(h6, s2)

        self.addLink(r1, s1)   # r1-eth0 connected to s1
        self.addLink(r1, s2)   # r1-eth1 connected to s2

def configure_and_run():
    setLogLevel('info')
    topo = L3Topo()
    net = Mininet(topo=topo, controller=None, switch=OVSSwitch, link=TCLink)
    # add remote POX controller (adjust IP to your POX container)
    c0 = net.addController('c0', controller=RemoteController, ip='172.20.200.10', port=6633)
    net.start()
    time.sleep(1)
    r1 = net.get('r1')
    # configure r1 interfaces for subnets
    r1.cmd('ifconfig r1-eth0 10.0.1.1/24')
    r1.cmd('ifconfig r1-eth1 10.0.2.1/24')
    r1.cmd('sysctl -w net.ipv4.ip_forward=1')

    # configure default route on hosts
    for hn in ['h1','h2','h3']:
        net.get(hn).cmd('ip route add default via 10.0.1.1')
    for hn in ['h4','h5','h6']:
        net.get(hn).cmd('ip route add default via 10.0.2.1')

    # start simple web server on h1
    h1 = net.get('h1')
    h1.cmd('mkdir -p /home/mininet/www')
    h1.cmd('echo "<h1>CDSI 2025 - Serveur Web</h1>" > /home/mininet/www/index.html')
    h1.cmd('busybox httpd -f -p 8080 -h /home/mininet/www &')

    info("*** Topologie démarrée. Tests rapides:\n")
    info(net.get('h4').cmd('curl -s -m 2 http://10.0.1.10:8080 || true')[:200] + "\n")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    configure_and_run()
