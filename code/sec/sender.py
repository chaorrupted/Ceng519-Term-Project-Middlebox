import os
import socket
import time

from netfilterqueue import NetfilterQueue as nfq
from scapy.all import *

def fake_record_route_data(chunks=1):  # encode our secret messages here rather than using all 0s
	if chunks >= 10:
		raise Exception('exceed the max length of ip header')
	length = chr(chunks*4+3)
	option_head = b'\x07'+length.encode()+b'\x04'  # todo: make the pointer point to the end
	route_data = "".join(['\x01']*4*chunks)  # message goes here
	option = option_head+('%s'%route_data).encode()
	return option


def packet_listener(packet):
    # print("Packet listener")
    scapy_packet = IP(packet.get_payload())

    # print("packet before : ")
    # IP(packet.get_payload()).show()

    if scapy_packet.haslayer(IP):  
        # parameter 1: randomly allow some % of packets on the network to prevent suspicious slow downs on host
        #scapy_packet[IP].chksum = None
        #scapy_packet[IP].len = None

        ip_packet = scapy_packet[IP]
        ip_packet.chksum = None
        ip_packet.len = None
        ip_packet.ttl = 128



        payload_packet = IP(packet.get_payload()).payload
        
        del ip_packet.payload

        option_length = 2
        ip_packet.ihl += (option_length + 1)
        ip_packet.options = IPOption(fake_record_route_data(option_length))
        
        rebuilt_packet = ip_packet / payload_packet
        packet.set_payload(bytes(rebuilt_packet))

    # print("packet rebuilt : ")
    # IP(packet.get_payload()).show()
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