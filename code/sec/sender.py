import os
import socket
import time

from netfilterqueue import NetfilterQueue as nfq
from scapy.all import *

def packet_listener(packet):
    # print("Packet listener")
    scapy_packet = IP(packet.get_payload())

    print("packet before : ")
    IP(packet.get_payload()).show()

    if scapy_packet.haslayer(IP):
        # print("IP layer")
        scapy_packet[IP].chksum = None
        scapy_packet[IP].len = None

        scapy_packet[IP].ttl = 128
        
        rebuilt_packet = Ether(scapy_packet.build())
        packet.set_payload(bytes(rebuilt_packet))

    print("packet after : ")
    IP(packet.get_payload()).show()
    packet.accept()

def setup_nfqueue():
    os.system('iptables -I OUTPUT -j NFQUEUE --queue-num 1')

    queue = nfq()
    # print("nfq")
    queue.bind(1, packet_listener)
    # print("bind")
    queue.run()
    # print("run")


if __name__ == "__main__":
    setup_nfqueue()