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

description: test script
        
"""


from tcp_stream import *
from tcp_state import *

import couchdb

#dbname = ''
#import tcp_sm
#from tcp_sm import tcp_stream_extractor
#t = tcp_stream_extractor.TCPStreamExtractor(filename)

#dbServer = couchdb.Server()
#db = dbServer.create('')

def store_stream_information(stream):
    stream_name = stream.get_stream_name()
    stream_keys = stream.get_stream_keys()
    stream_summary = stream.get_app_stream_summary()
    
    stream_fields = {}
    for summary in stream_summary:
		i = 0
		while i < len(stream_keys):
			stream_fields[stream_keys[i]] = summary[i]
			i+=1
    
    doc = db[stream_name]
    for timestamp in stream_fields:
        doc[timestampe] = stream_fields[timestamp]
    


tcp_pkts = []

filename = "output.pcap"
filename = "../sample_packets.pcap"

p = scapy.utils.PcapReader(filename)

for i in p:
    if 'TCP' in i: tcp_pkts.append(i)
    

tcp_states = {}


pkt = tcp_pkts[0]

# able to create TCP States albeit they are wrong, I can still create them
for pkt in tcp_pkts:
	flow = (create_forward_flow(pkt), create_reverse_flow(pkt))
	if not flow[0] in tcp_states and\
		not flow[1] in tcp_states and is_syn_pkt(pkt):
		#print ("yay!")
		iiopoi = pkt
		tcp_states[flow[0]] = TCPStateMachine(pkt)
		tcp_states[flow[1]] = tcp_states[flow[0]] 
	elif flow[0] in tcp_states:
		iiopoi = tcp_states[flow[0]].next_state(pkt)


states = []
for k in tcp_states.keys():
    if not tcp_states[k] in states: 
        states.append(tcp_states[k])
        
        
i = 0
#while i < len(states):
#    print i, states[i].flows
#    i += 1


# lets try doing some stuff with streams now    
tcp_streams = {}
for pkt in tcp_pkts:
	flow = (create_forward_flow(pkt), create_reverse_flow(pkt))
	if not flow[0] in tcp_streams and\
		not flow[1] in tcp_streams and is_syn_pkt(pkt):
		#print ("yay!")
		#pkt
		tcp_streams[flow[0]] = TCPStream(pkt)
		tcp_streams[flow[1]] = tcp_streams[flow[0]] 
	elif flow[0] in tcp_streams:
		iiopoi = tcp_streams[flow[0]].add_pkt(pkt)


streams = []
for k in tcp_streams.keys():
    if not tcp_streams[k] in streams: 
        streams.append(tcp_streams[k])
        
        
i = 0
#while i < len(streams):
#    print i, streams[i].flows
#    i += 1


#ssh_stream = streams[1]
#ssh_stream.get_app_stream_summary()

print ("streams extracted: ",len(streams))

open_streams = []
closed_streams = []
prehs_streams = []
other_streams = []

for stream in streams:
    if stream.tcp_state.is_closed():
        closed_streams.append(stream)
    elif stream.tcp_state.is_established():
        open_streams.append(stream)
    elif stream.tcp_state.is_prehandshake():
        prehs_streams.append(stream)
    else:
        other_streams.append(stream)

def print_streams_states(streams):
	other_streams = streams
	i = 0
	while i < len(other_streams):
		print (i, other_streams[i].tcp_state.get_states())
		i += 1


def print_step_by_step_state(stream):
	g = stream
	test = [i for i in g.get_order_pkts()]
	tcp_stream = TCPStream(test[0])
	i = 1
	while i < len(test):
		tcp_stream.add_pkt(test[i])
		print tcp_stream.tcp_state.get_states()
		i+=1

print_streams_states(other_streams)

