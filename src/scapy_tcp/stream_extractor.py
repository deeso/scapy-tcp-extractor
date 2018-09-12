"""
TCP stream extraction using Scapy.

(c) Praetorian 
Author: Adam Pridgen <adam.pridgen@praetorian.com> || <adam.pridgen@thecoverofnight.com>



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

Description: tracks extracted streams [TCPStream] and removes the streams if they are timedout
    
"""


import scapy, threading
import gc
from threading import *
from random import randint
from scapy.all import *

from .tcp_stream import *
from .tcp_state import *

CLEANUP = True
CLEANUP_THREAD = None



def thread_maintanence(timer_val, stream_extractor, timeout=1000):
    new_threads = []
    print ("Maintanence thread was called!")
    stream_extractor.cleanup_timedout_streams(timeout)
    if not stream_extractor.cleanup:
        print ("Maintanence thread was called, but nothing to maintain")
        return
    #gc.collect()
    CLEANUP_THREAD = threading.Timer(timer_val, thread_maintanence, args=(timer_val,stream_extractor ))
    CLEANUP_THREAD.start()
        
        


class TCPStreamExtractor:
    def __init__(self, filename, packet_list=None, process_packets=True, 
                 outputdir=None, pcap_filters=None):
        self.filename = filename
        
        self.pcap_filter = pcap_filters
        self.outputdir=outputdir
        
        if not self.outputdir is None:
            if not os.path.exists(self.outputdir):
                os.mkdir(self.outputdir)
            if not os.path.exists(os.path.join(self.outputdir, "pcaps")):
                os.mkdir(os.path.join(self.outputdir, "pcaps"))
            if not os.path.exists(os.path.join(self.outputdir, "flows")):
                os.mkdir(os.path.join(self.outputdir, "flows"))
        
        self.packet_list = packet_list
        if packet_list is None:
            self.packet_list =scapy.utils.rdpcap(filename) 
        
        self.pkt_num = 0
        # a stream is mapped under two flow keys
        self.streams = {}
        self.timestamp = 0
        self.DEL_LOCK = threading.Lock()
        self.cleanup = True
        self.timer = 4.0
        self.data_streams = {}
        self.fwd_flows = set()
        self.rev_flows = set()

        
        if process_packets:
            self.process_packets()
                
        
    def __next__(self):
        if self.pkt_num >= len(self.packet_list):
            return None  
        pkt = self.packet_list[self.pkt_num]
        self.pkt_num += 1
        self.timestamp = int(pkt.time)
        if not 'TCP' in pkt:
            return pkt
        
        fwd_flows = set()
        rev_flows = set()

        flow = (create_forward_flow(pkt), create_reverse_flow(pkt))
        if not flow[0] in self.streams and\
            not flow[1] in self.streams and is_syn_pkt(pkt):
            self.streams [flow[0]] = TCPStream(pkt)
            self.streams [flow[1]] = self.streams [flow[0]]
            self.fwd_flows.add(flow[0])
            self.rev_flows.add(flow[1])
        elif flow[0] in self.streams:
            self.streams[flow[0]].add_pkt(pkt)        
        return pkt

    def process_packets(self):
        while self.pkt_num < len(self.packet_list):
            next(self)

        # create data streams
        for session in self.fwd_flows:
            tcp_stream = self.streams[session]
            self.data_streams[session] = tcp_stream.get_stream_data()
        return self.pkt_num, self.data_streams

    def summary(self):
        flows = sorted(list(self.fwd_flows))
        fmt = "{} (c) {}  (s) {}"
        c = lambda f: int(f.split(':')[1].split()[0])
        s = lambda f: int(f.split(':')[-1])
        results = []
        for sess in flows:                                                                   
            http = self.streams[sess]
            f = fmt.format(sess, len(http[c(sess)]) len(http[s(sess)]) )
            results.append(f)
        print ('\n'.join(results))
        return results

    def run(self):
        global CLEANUP_THREAD
        try:
            CLEANUP_THREAD = threading.Timer(self.timer, thread_maintanence, args=(self.timer, self ))
            CLEANUP_THREAD.start() # Duh! me needs to start or nom nom nom memories!
            self.process_packets()
        except KeyboardInterrupt:
            self.cleanup = False
            CLEANUP_THREAD.cancel()
            if CLEANUP_THREAD.is_alive():
                CLEANUP_THREAD.join()

        except StopIteration:
            self.cleanup = False
            CLEANUP_THREAD.cancel()
            if CLEANUP_THREAD.is_alive():
                CLEANUP_THREAD.join()
            streams = list(self.streams.keys())
            for stream in streams:
                self.write_stream(stream)


    def cleanup_timedout_streams(self, timeout=180.0):
        timestamp = self.timestamp
        purged_streams = set()
        
        # dont want streams changing underneath us
        keys = list(self.streams.keys())
        for key in keys:
            if not key in self.streams:
                continue
            pkt_cnt = self.streams[key].len_pkts()
            l_ts = int(self.streams[key].time)
            if (timestamp - l_ts) > timeout:
                print(("Timeout occurred: %s - %s => %s, Writing stream: %s"%(str(timestamp),str(l_ts), str(timestamp-l_ts), key)))
                purged_streams.add(key)
                self.write_stream(key)
                self.remove_stream(key)
                print(("%s purged from current streams"%key))
        
            elif pkt_cnt > 10000:
                print(("Writing %d of %d packets from stream: %s"%(pkt_cnt,self.streams[key].len_pkts(), self.streams[key].get_stream_name()))) 
                self.write_stream(key, pkt_cnt)
                self.streams[key].destroy(pkt_cnt)
                print(("***Wrote %d packets for stream: %s"%(pkt_cnt,self.streams[key].get_stream_name()))) 
        print(("Purged %d streams of %d from evaluated streams\n\n"%(len(purged_streams), len(keys)/2))) 

    def get_streams(self):
        return self.data_streams

    def remove_stream(self, key):
        # dont call in cleanup stream, it will deadlock
        if not key in self.streams:
            return
        self.DEL_LOCK.acquire()
        flows = self.streams[key].flows
        self.streams[list(flows)[0]].destroy()
        for i in flows:
            #self.streams[i].destroy()
            del self.streams[i]
        self.DEL_LOCK.release()
        
    def write_stream(self, key,pkts_cnt=0):
        if not key in self.streams:
            return
        self.DEL_LOCK.acquire()
        stream = self.streams[key]
        stream_name = stream.get_stream_name()
        filename = stream_name
        pcap_fname = filename
        flow_fname = filename
        
        if not self.outputdir is None:
            odir = os.path.join(self.outputdir, "pcaps")
            pcap_fname = os.path.join(odir, stream_name)
            odir = os.path.join(self.outputdir, "flows")
            flow_fname = os.path.join(odir, stream_name)
            
        stream.write_pcap(pcap_fname, pkts_cnt)
        stream.write_flow(flow_fname, pkts_cnt)
                
        self.DEL_LOCK.release()
