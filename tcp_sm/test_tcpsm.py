import scapy
from scapy import all

p = scapy.utils.PcapReader("../output.pcap")

tcp_pkts = []

while True:
    f = next(p)
    if f is None:
        break
    if 'TCP' in f:
        tcp_pkts.append(f)