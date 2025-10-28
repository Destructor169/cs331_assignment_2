#!/usr/bin/env python
from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
import os
def create_topology():
    # Create network
    net = Mininet(controller=Controller, link=TCLink)
    net.addController('c0')
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')
    s3 = net.addSwitch('s3')
    s4 = net.addSwitch('s4')
    print("switches added")
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    h3 = net.addHost('h3', ip='10.0.0.3/24')
    h4 = net.addHost('h4', ip='10.0.0.4/24')
    print("4 hosts added")
    dns = net.addHost('dns', ip='10.0.0.5/24')
    print("dns added")
    net.addLink(h1, s1, bw=100, delay='2ms')
    net.addLink(h2, s2, bw=100, delay='2ms')
    net.addLink(h3, s3, bw=100, delay='2ms')
    net.addLink(h4, s4, bw=100, delay='2ms')
    net.addLink(s1, s2, bw=100, delay='5ms')
    net.addLink(s2, s3, bw=100, delay='8ms')
    net.addLink(s3, s4, bw=100, delay='10ms')
    net.addLink(dns, s2, bw=100, delay='1ms')
    print("added all links")
    net.start()    
    print("*** starting network and Testing connectivity")
    net.pingAll()
    print("*** Network is ready")
    print("Hosts: h1(10.0.0.1), h2(10.0.0.2), h3(10.0.0.3), h4(10.0.0.4)")
    print("DNS Resolver: dns(10.0.2.0)")
    # Open CLI for manual testing
    print("*** Adding veth to connect to root namespace")
    import os
    import time
  # Clean any old interfaces
    os.system("sudo ip link del veth-mininet type veth peer name veth-root 2>/dev/null || true")

    # Create veth pair
    os.system("sudo ip link add veth-mininet type veth peer name veth-root")

    # Bring both up
    os.system("sudo ip link set veth-mininet up")
    os.system("sudo ip link set veth-root up")

    # Attach one end to OVS switch s1
    os.system("sudo ovs-vsctl --may-exist add-port s2 veth-mininet")

    # Assign IP to the root side (host namespace)
    os.system("sudo ip addr flush dev veth-root")
    os.system("sudo ip addr add 10.0.0.254/24 dev veth-root")

    # Enable forwarding on host
    os.system("sudo sysctl -w net.ipv4.ip_forward=1")

    # Flush and set up NAT/forwarding rules
    os.system("sudo iptables -t nat -F")
    os.system("sudo iptables -F FORWARD")
    os.system("sudo iptables -A FORWARD -i veth-root -o eth0 -j ACCEPT")
    os.system("sudo iptables -A FORWARD -i eth0 -o veth-root -m state --state RELATED,ESTABLISHED -j ACCEPT")
    os.system("sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")

    # Wait for interface to settle
    time.sleep(5)
    dns.cmd("sudo ip route add default via 10.0.0.254")
    for h in [h1,h2,h3,h4]: 
        h.cmd("echo 'nameserver 10.0.0.5' > /etc/resolv.conf")
        
    dns.cmd("sudo stdbuf -oL python3 finalresolver.py > dns.txt 2>&1 &")

    CLI(net)
    print("*** Stopping network")
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()
