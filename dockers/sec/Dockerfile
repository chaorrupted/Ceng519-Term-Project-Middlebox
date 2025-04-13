FROM ubuntu:latest

#RUN apt update && apt install -y tshark iproute2 iptables dnsmasq jq netmask bsdmainutils conntrack iputils-ping dnsutils  net-tools 
RUN apt update -y && apt upgrade -y && apt install -y systemd tshark jq iputils-ping dnsutils  net-tools iperf tcpdump netcat-traditional curl  iproute2 ethtool iptables nftables

RUN echo 'net.ipv4.ip_forward=0' >> /etc/sysctl.conf && sysctl -p

RUN apt update && apt install -y python3 python3-pip python3-scapy python3-dev libnetfilter-queue-dev build-essential pipx cmake libpcap-dev  vim

RUN pip3 install netfilterqueue --break-system-packages

WORKDIR /code/sec