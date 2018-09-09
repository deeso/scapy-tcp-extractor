"""

(c) Praetorian 
Author: Adam Pridgen <adam.pridgen@praetorian.com>
         <adam.pridgen@thecoverofnight.com>

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the Free
Software Foundation; either version 3, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along
with this program; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
02110-1301, USA.

description: broken code
        
"""

from scapy.all import *
from random import randint
from tcp_snd import snd
from tcp_rcv import rcv



MAX = 2 ** 32 - 1



        






class ReadTCPCapture(TCPState):
    def __init__(self, pcap_file_name, filter_ports=[]):
        fports = set(filter_ports)
        pcap = scapy.rdpcap(pcap_file_name)
        self.pkts = [pkt for pkt in pcap if TCP in pkt and\
                     pkt[TCP].sports not in fports and\
                     pkt[TCP].dport not in fports]
        self.streams = None
        self.sessions = {}
        self.states = {}
    
    def filter_tcp(self, pkts, src=None, dst=None, sport=None, dport=None, seq=None):
        results = []
        check = lambda arg,comp: not arg is None and comp != arg 
        for pkt in self.pkts:
            if check(src, pkt.src):
                continue
            if check(dst, pkt.dst):
                continue
            if check(sport, pkt.sport) and check(sport, pkt.dport):
                continue
            if check(dport, pkt.dport) and check(dport, pkt.sport):
                continue
            results.append(pkt)
        return results
        
    def read_tcp_stream(self, src=None, dst=None, sport=None, dport=None, seq=None):
        pkts = self.filter_tcp(src, dst, sport, dport)
        return pkts
    
    def find_est_conn(self, pkts, pos):
        s_pos = pos
        get_filter_vals = lambda pkt:pkt.src, pkt.dst, pkt.sport, pkt.dport
        while s_pos < len(pkts):
            # get current packet and check to see if it is a SYN
            c_pkt = pkts[s_pos]
            if c_pkt[TCP].flags != self.get_flag_val("S"):
                s_pos+=1
                continue
            # grab all the remaining pkts/segments that match the c_pkt criterion
            stream_pkts = self.filter_tcp(pkts[s_pos:], get_filter_vals(c_pkt))
            if len(stream_pkts) > 3 and\
                stream_pkts[1][TCP].flags == self.get_flag_val("A") and\
                stream_pkts[2][TCP].flags == self.get_flag_val("SA"):
                end_pos = self.find_finack(stream_pkts)
                return stream_pkts[:end_pos], s_pos
            s_pos+=1
        return [],s_pos
    
    def find_finack(self, pkts):
        pos = 0
        while pos < len(pkts):
            pkt = pkts[pos]
            if pkt[TCP].flags == self.get_flag_val("FA"):
                break
            pos+=1
        return pos
        
    def get_next_stream(self, pkts, pos):
        est_pos = find_establish_conn(pkts, pos)
    
    def slice_tcp_streams(self, pkts=None):
        pkt_s = pkts
        pkts = None
        if pkt_s is None:
            pkt_s = self.pkts
        self.streams = []
        while pos <  len(pkt_s):
            pos, stream = self.get_next_stream(pkts, pos)
            self.streams.append(stream)





class ReadTCPCapture(TCPState):
    def __init__(self, pcap_file_name, filter_ports=[]):
        fports = set(filter_ports)
        pcap = scapy.rdpcap(pcap_file_name)
        self.pkts = [pkt for pkt in pcap if TCP in pkt and\
                     pkt[TCP].sports not in fports and\
                     pkt[TCP].dport not in fports]
        self.streams = None
        self.sessions = {}
        self.states = {}
    
    def filter_tcp(self, pkts, src=None, dst=None, sport=None, dport=None, seq=None):
        results = []
        check = lambda arg,comp: not arg is None and comp != arg 
        for pkt in self.pkts:
            if check(src, pkt.src):
                continue
            if check(dst, pkt.dst):
                continue
            if check(sport, pkt.sport) and check(sport, pkt.dport):
                continue
            if check(dport, pkt.dport) and check(dport, pkt.sport):
                continue
            results.append(pkt)
        return results
        
    def read_tcp_stream(self, src=None, dst=None, sport=None, dport=None, seq=None):
        pkts = self.filter_tcp(src, dst, sport, dport)
        return pkts
    
    def find_est_conn(self, pkts, pos):
        s_pos = pos
        get_filter_vals = lambda pkt:pkt.src, pkt.dst, pkt.sport, pkt.dport
        while s_pos < len(pkts):
            # get current packet and check to see if it is a SYN
            c_pkt = pkts[s_pos]
            if c_pkt[TCP].flags != self.get_flag_val("S"):
                s_pos+=1
                continue
            # grab all the remaining pkts/segments that match the c_pkt criterion
            stream_pkts = self.filter_tcp(pkts[s_pos:], get_filter_vals(c_pkt))
            if len(stream_pkts) > 3 and\
                stream_pkts[1][TCP].flags == self.get_flag_val("A") and\
                stream_pkts[2][TCP].flags == self.get_flag_val("SA"):
                end_pos = self.find_finack(stream_pkts)
                return stream_pkts[:end_pos], s_pos
            s_pos+=1
        return [],s_pos
    
    def find_finack(self, pkts):
        pos = 0
        while pos < len(pkts):
            pkt = pkts[pos]
            if pkt[TCP].flags == self.get_flag_val("FA"):
                break
            pos+=1
        return pos
        
    def get_next_stream(self, pkts, pos):
        est_pos = find_establish_conn(pkts, pos)
    
    def slice_tcp_streams(self, pkts=None):
        pkt_s = pkts
        pkts = None
        if pkt_s is None:
            pkt_s = self.pkts
        self.streams = []
        while pos <  len(pkt_s):
            pos, stream = self.get_next_stream(pkts, pos)
            self.streams.append(stream)
