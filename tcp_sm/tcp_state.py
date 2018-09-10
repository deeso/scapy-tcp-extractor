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

Description: tracks TCPStream state between a client and server
    
"""
from scapy.all import *
from random import randint
from .tcp_snd import Snd
from .tcp_rcv import Rcv


is_syn_pkt = lambda pkt: 'TCP' in pkt and pkt['TCP'].flags == TCP_FLAGS['S']
is_synack_pkt = lambda pkt: 'TCP' in pkt and pkt['TCP'].flags == (TCP_FLAGS['S'] | TCP_FLAGS['A'])

create_pkt_flow = lambda pkt: "%s:%s ==> %s:%s"%(pkt['IP'].src,str(pkt['IP'].sport),pkt['IP'].dst,str(pkt['IP'].dport))

create_forward_flow = lambda pkt: "%s:%s ==> %s:%s"%(pkt['IP'].src,str(pkt['IP'].sport),pkt['IP'].dst,str(pkt['IP'].dport))

create_reverse_flow = lambda pkt: "%s:%s ==> %s:%s"%(pkt['IP'].dst,str(pkt['IP'].dport),pkt['IP'].src,str(pkt['IP'].sport))


create_flow = create_forward_flow


TCP_FLAGS = {"F":0x1, "S":0x2, "R":0x4, "P":0x8,
              "A":0x10, "U":0x20, "E":0x40, "C":0x80,
              0x1:"F", 0x2:"S", 0x4:"R", 0x8:"P",
              0x10:"A", 0x20:"U", 0x40:"E", 0x80:"C"}

TCP_STATES = {"LISTEN":{'S':["SYN_RCVD", 'SA']},
              "SYN_SENT":{'SA':["ESTABLISHED", 'A'],'S':["SYN_RCVD", 'SA'],},
              "SYN_RCVD":{'F':["FIN_WAIT_1", 'A'],'A':["ESTABLISHED", ''],'R':["LISTEN", ''],},
              "LAST_ACK":{},
              "CLOSE_WAIT":{"":["LAST_ACK","F"]}, # initiated by the server
              "LAST_ACK":{"A":["CLOSED",""]},
              "ESTABLISHED":{"F":["FIN_WAIT_1",""],},
              "FIN_WAIT_1":{"A":["FIN_WAIT_2",""],"F":["CLOSED","A"],"FA":["TIME_WAIT","A"],},
              "FIN_WAIT_2":{"F":["TIME_WAIT","A"],},
              "CLOSED":{"A":["TIME_WAIT", ""]},}
                   

flags_equal = lambda pkt, flag: pkt['TCP'].flags == flag
flags_set = lambda pkt, flag: (pkt['TCP'].flags & flag) != 0

class TCPStateMachine:
    def __init__(self, pkt=None):
        if not pkt is None:
	        self.init(pkt)
    
    def init(self, pkt):
        if not 'TCP' in pkt:
            raise Exception("Not a TCP Packet")
        if not is_syn_pkt(pkt):
            raise Exception("Not valid SYN")
            
        self.flows = set((create_forward_flow(pkt), create_reverse_flow(pkt)))
        self.server = pkt['IP'].dst
        self.client = pkt['IP'].src
        
        # 0 is now, 1 is the future Flags
        self.server_state = "LISTEN"
        self.client_state = "SYN_SENT"
        
        self.server_close_time = -1.0
        self.client_close_time = -1.0
        self.fin_wait_time = -1.0
        
        
        
    def next_state(self, pkt):
        if not 'TCP' in pkt:
            raise Exception("Not a TCP Packet")
        
        # determine in what context we are handling this packet
        flow = create_flow(pkt)
        if flow not in self.flows:
            raise Exception("Not a valid packet for this model")
        
        if pkt['IP'].dst == self.server:
            v =  self.handle_client_pkt(pkt)
            if self.is_fin_wait():
               self.fin_wait_time = pkt.time
            return v
        else:
            v = self.handle_server_pkt(pkt)
            if self.is_fin_wait():
               self.fin_wait_time = pkt.time
            return v
            
        
        raise Exception("Not a valid packet for this model")
        
    
    def get_states(self):
        return (self.client_state, self.server_state)
        
    
    def build_flags(self, sflags):
        return sum([TCP_FLAGS[i] for i in sflags])
        
    
    def active_close(self):
        return (self.client_state == self.server_state and self.server_state == "CLOSED")
    
    def passive_close(self):
        return (self.client_state == "LAST_ACK" and self.server_state == "CLOSE_WAIT")
    
    def is_established(self):
        return (self.client_state == self.server_state and self.server_state == "ESTABLISHED")
    
    def client_prehandshake(self):
        return (self.client_state == "SYN_SENT") or (self.client_state == "SYN_RCVD")
	
    def server_prehandshake(self):
	    return (self.server_state == "SYN_SENT") or (self.server_state == "SYN_RCVD") or (self.server_state == "LISTEN")
    
    def is_fin_wait(self):
        return self.client_state.find("FIN_WAIT") > -1 or self.server_state.find("FIN_WAIT") > -1
    def is_prehandshake(self):
        return self.client_prehandshake() and self.server_prehandshake()
    
    def is_closed(self):
        return self.passive_close() or self.active_close()
    
    def handle_client_pkt(self, pkt):
        flags = pkt['TCP'].flags
        client_got_closed = False
        server_got_closed = False
        
        if flags == self.build_flags("R"):
            self.client_state = "CLOSED"
            self.server_state = "CLOSED"
            server_got_closed = True
            client_got_closed = True

        elif flags == self.build_flags("RA"):
            self.client_state = "CLOSED"
            self.server_state = "CLOSED"
            server_got_closed = True
            client_got_closed = True
        elif flags == self.build_flags("S"):
            self.server_state = "SYN_SENT"

        elif self.client_state == "SYN_SENT":
             if flags & self.build_flags("A") > 0:
                 self.client_state = "ESTABLISHED"
                 self.server_state = "ESTABLISHED"
             else:
                 self.client_state = "CLOSED"
                 server_got_closed = pkt.time 
                 client_got_closed = pkt.time
                 return self.is_closed()
            
        elif self.client_state == "SYN_SENT":
            if flags & self.build_flags("SA") > 0:
                self.client_state = "SYN_RCVD"
            
        elif self.client_state == "SYN_RECVD" and\
              flags & self.build_flags("F") > 0:
                self.client_state = "FIN_WAIT_1"

        elif self.client_state == "ESTABLISHED" and\
            flags == self.build_flags("FA"):
            self.client_state = "FIN_WAIT_1"
        
        elif self.client_state == "FIN_WAIT_1" and\
            flags == self.build_flags("A"):
            self.client_state = "CLOSED"
        
        elif self.client_state == "ESTABLISHED" and\
            self.server_state == "CLOSE_WAIT" and\
            flags & self.build_flags("A") > 0:
            self.client_state = "CLOSED"
        
        if self.server_state == "FIN_WAIT_1" and\
        	self.client_state == "CLOSED" and\
            flags == self.build_flags("A"):
            self.server_state = "CLOSED"
            server_got_closed = True
            client_got_closed = True
        
        if client_got_closed:
            self.client_close_timed = pkt.time
        if server_got_closed:
            self.server_close_timed = pkt.time
            
        return self.is_closed()
        
    def handle_server_pkt(self, pkt):
        flags = pkt['TCP'].flags
        server_got_closed = False
        client_got_closed = False

        if flags == self.build_flags("R"):
            self.client_state = "CLOSED"
            self.server_state = "CLOSED"
            server_got_closed = True
            client_got_closed = True

        elif flags == self.build_flags("RA"):
            self.client_state = "CLOSED"
            self.server_state = "CLOSED"
            server_got_closed = True
            client_got_closed = True

        elif flags == self.build_flags("S"):
            self.server_state = "SYN_SENT"
        elif self.server_state == "LISTEN" and\
            flags == self.build_flags("SA"):
            self.server_state = "SYN_RCVD"
        
        elif self.server_state == "ESTABLISHED" and\
            flags == self.build_flags("FA"):
            self.server_state = "FIN_WAIT_1"
        
        elif self.server_state == "FIN_WAIT_1" and\
            flags == self.build_flags("A"):
            self.server_state = "CLOSED"
            server_got_closed = True

        
        elif self.server_state == "SYN_RCVD" and\
            flags == self.build_flags("F"):
            self.server_state = "FIN_WAIT_1"
        
        elif self.server_state == "FIN_WAIT_1" and\
            flags == self.build_flags("FA"):
            self.server_state = "CLOSED"
            
        elif self.server_state == "SYN_RCVD" and\
            flags == self.build_flags("A"):
            self.server_state = "ESTABLISHED"
        
        elif self.server_state == "ESTABLISHED" and\
            flags & self.build_flags("F") > 0:
            self.server_state = "CLOSE_WAIT"
        
        elif self.client_state == "FIN_WAIT_1" and\
            flags == self.build_flags("FA"):
            self.server_state = "CLOSED"                    
            server_got_closed = True
            
        elif self.client_state == "CLOSED" and\
            flags == self.build_flags("A"):
            self.server_state = "CLOSED"
            server_got_closed = True
                
        if self.client_state == "FIN_WAIT_1" and\
        	self.server_state == "CLOSED" and\
            flags == self.build_flags("A"):
            self.client_state = "CLOSED"
            client_got_closed = True
        
        if client_got_closed:
            self.client_close_timed = pkt.time
        if server_got_closed:
            self.server_close_timed = pkt.time

        return self.is_closed()



#@conf.commands.register
class TCPState:
    '''
    Basic implementation of the TCP State Machine (SM) that 
    is meant to work with scapy.

    Reference RFC 793.  TCP not fully implemented.  This installment gives
    no attention to timers, congestion windows, etc.  This is a basic protocol
    implementation so that we can talk to our estranged partner host.
    '''
    
    def __init__(self):
        # RCV should actually be initialized when the 
        # 3-way hand shake takes place
        irs = randint(0, 0x0FFFFFFFF)
        iss = randint(0, 0x0FFFFFFFF)
        print(("Initializing the SND with %x and RCV with %x" % (iss,irs)))
        self.SND = Snd()
        self.RCV = Rcv()
        self.seg_record = []# keep record of session  
        self.una_segs = []    # maintain list of un-acked segs
        self.previous_payload = None # for ans TCP data send
        self.state = "CLOSED"
        self.sock = None
        self.move_state = self.state_closed
        # TCP segment info
        self.sport = randint(0, 0x0FFFFFFFF)
        self.dport = randint(0, 0x0FFFFFFFF)
        self.dst = 'localhost'
         
    def get_socket(self, s):
        if not s is None:
            self.sock = s
            s = None
        elif s is None and self.sock is None:
            self.sock = self.init_socket()
    
    def get_pkt(self, pkt):
        p = pkt
        if p is None:
            p = self.get_base_pkt()
        return p

    def add_ether(self, pkt):
        if Ether not in pkt:
            return Ether() / pkt
        return pkt
    
    def check_flags(self, seg, flag_str):
        '''
        Compare segment flag values to a flag string.

        :param seg: segment to compare flag values 
        :type seg:  scapy.TCP
        :param flag_str: flag string to compare against the 
        :type flag_str:  string
                         segment
        :return: flag values match 
        :rtype: boolean
        '''
        return self.get_flag_val(flag_str) == seg.flags
    
    def init_from_pkt(self, seg):
        '''
        Initialize the TCP SM based on a TCP segment.

        :param seg: segment to initialize SM from 
        :type seg:  scapy.TCP
        '''        
        self.RCV.init_from_seg(seg)
        self.SND.init_from_seg(seg)
        
    def build_basic_pkt(self, dst, dport, sport=None):
        if sport is None:
            sport = randint(0, 65535)
        self.sport = sport
        self.dport = dport
        self.dst = dst
        return IP(dst=dst) / TCP(dport=dport, sport=sport)
        
    def get_rbase_tcp(self, rseg):
        '''
        Creates a base TCP segment based on a rcvd segment.

        :param rseg: rcvd segment to base a new segment off of 
        :type rseg:  scapy.TCP
        '''
        sport = rseg.dport
        dport = rseg.sport
        options = rseg.options
        return TCP(sport=sport, dport=dport, options=options)
    
    def get_rbase_ip(self, rpkt):
        '''
        Creates a base IP packet based on a rcvd segment.

        :param rpkt: rcvd IP packet to base a new packet off of 
        :type rpkt:  scapy.IP
        '''        
        dst = rpkt.src
        src = rpkt.dst
        options = rpkt.options
        return IP(src=src, dst=dst, options=options)
    
    def get_rbase_pkt(self, rpkt):
        '''
        Creates a base packet based on a rcvd packet.

        :param rpkt: rcvd segment to base a new packet off of 
        :type rpkt:  scapy.IP/scapy.TCP
        '''
        return IP(dst=rpkt[IP].src) / TCP(dport=rpkt[TCP].sport, sport=rpkt[TCP].dport)

    def get_base_tcp(self):
        '''
        Creates a base TCP segment based on a defined internal TCP parameters
        segment.
        '''
        sport = self.sport
        dport = self.dport
        return TCP(sport=sport, dport=dport)
    
    def get_base_ip(self):
        '''
        Creates a base IP packet based on internal TCP/IP stuffs.
        '''        
        dst = self.dst
        return IP(dst=dst)
    
    def get_base_pkt(self):
        '''
        Creates a base packet based on a rcvd packet.
        '''
        return IP(dst=self.dst) / TCP(dport=self.dport,sport=self.sport)

        
    def update_seg_state(self, seg, payload=None):
        '''
        Update the state of a segment based on the TCP state.

        :param seg: segment to update the ack and seq numbers for 
        :type seg:  scapy.TCP
        '''
        seg = self.RCV.update_seg(seg)[0]
        seg, pay = self.SND.update_seg(seg, payload)
        return seg, pay

    def get_flag_val(self, flag_str):
        '''
        Get flag values based on flag string.

        :param flag_str: flag string to convert to int
        :type flag_str: string  

        :return: integer representation of the flag string
        :rtype: integer
        '''
        flags = 0
        for i in flag_str:
            flags += TCP_FLAGS[i]
        return flags
    
    def check_pkt(self, pkt):
        '''
        Check to see if the pkt contains a TCP segment.

        :param pkt: packet that may or may not contain a pkt
        :type pkt: scapy.Packet

        :return: TCP payload is in the packet
        :rtype: boolean
        '''
        return not pkt is None and TCP in pkt
            
    def update_from_pkt(self, pkt):
        '''
        Update TCP state from the given packet.

        :param pkt: packet that is used to update TCP state
        :type pkt: scapy.Packet

        :return: successful update            
        :rtype: boolean
        '''
        if self.check_pkt(pkt):
            seg = pkt[TCP]
            x = self.update_snd(seg)
            y = self.update_rcv(seg)
            return x and y
        return False
        
    def update_snd(self, seg):
        '''
        Update the SND (seq numbers and such) portion of the TCP SM.

        :param seg: TCP segment
        :type seg: scapy.TCP

        :return: successful update                        
        :rtype: boolean
        '''
        return self.SND.update_from_seg(seg)
    
    def update_rcv(self, seg):
        '''
        Update the RCV (rcv numbers and such) portion of the TCP SM.

        :param seg: TCP segment
        :type seg: scapy.TCP

        :return: successful update                        
        :rtype: boolean
        '''
        return self.RCV.update_from_seg(seg)
    
    # handle send syn stuff
    def create_seg(self, seg=None, flags="S", payload=None ):
        '''
        Create a segment based on the TCP SM, flags, and payload.

        :param seg: TCP segment
        :type seg: scapy.TCP
        :param flags: flags string to set in the segment
        :type flags: string
        :param payload: payload to include in the segment
        :type payload: string

        :return: tuple of the TCP segment and unused payload            
        
        :rtype: (scapy.TCP, string)
        '''
        s = self.get_pkt(seg)
        seg = None
        pay = payload
        payload = None
        s, pay = self.update_seg_state(s, pay)
        s.flags = self.get_flag_val(flags)
        return s, pay
    
    def rcv_syn(self, rpkt):
        '''
        Update TCP SM based on rcv'd syn packet.

        :param rpkt: IP/TCP pkt
        :type rpkt: scapy.Packet
        '''
        self.dport = seg.sport
        self.sport = seg.dport
        self.dst = seg.src

        # init tcp state
        self.RCV.init_from_seg(rpkt[TCP])
        self.state = "SYN_RCVD"

    def rcv_syn_ans(self, rpkt, s=None):
        '''
        Update TCP SM based on rcv'd a syn packet and 
        respond automatically.

        :param rpkt: IP/TCP pkt
        :type rpkt: scapy.Packet
        :param s: socket to send packet out on
        :type s: scapy.L3Socket
        '''
        self.get_socket(s)
        s = None

        self.rcv_syn(rpkt)
        # get IP and TCP vals
        pkt = self.get_base_pkt()
        self.state = "SYN_RCVD"
        self.move_state = self.state_synrcvd
        return self.send_pkt(pkt, self.sock, flags="SA")    
        
    def rcv_synack(self, rpkt):
        '''
        Update TCP SM based on rcv'd a syn-ack packet. 

        :param rpkt: IP/TCP pkt
        :type rpkt: scapy.Packet
        '''
        if self.check_pkt(rpkt):
            self.init_from_pkt(rpkt[TCP])
    
    def rcv_synack_ans(self, rpkt, s=None):
        '''
        Update TCP SM based on rcv'd a syn-ack packet and 
        respond automatically.

        :param rpkt: IP/TCP pkt
        :type rpkt: scapy.Packet
        :param s: socket to send packet out on
        :type s: scapy.L3Socket
        '''
        self.get_socket(s)
        s = None

        self.rcv_synack(rpkt)
        pkt = self.get_base_pkt()
        print ("Inside syn-ack ans machine")
        #rpkt.show()
        #pkt.show()
        return self.send_pkt(pkt, s, flags="A")
    
    def send_pkt(self, pkt=None, s=None, flags=None, payload=None):
        '''
        Update TCP Segment and Send the full packet. 

        :param s: socket to send packet out on
        :type s: scapy.L3Socket
        :param pkt: IP/TCP pkt
        :type pkt: scapy.Packet
        :param flags: flags to set in the segment
        :type flags: string
        :param payload: payload to include in the packet
        :type payload: string

        :return: packet received from sending the pkt                
    
        :rtype: scapy.Packet
        '''
        p = self.get_pkt(pkt)
        self.get_socket(s)
        s = pkt = None
                    
        #pkt = self.add_ether(pkt)
        p[TCP],pay = self.create_seg(p[TCP], flags=flags,payload=payload)
        rpkt = self.send_rcv_pkts(self.sock, p)
        if rpkt is None or not TCP in rpkt:
            return None, pay
        return rpkt, pay
    
    def rcv_fin(self, pkt):
        self.update_from_pkt(pkt)
            
    def rcv_fin_ans(self, rpkt, s=None):
        # skip over FIN_WAIT_* phases and
        # LAST_ACK states
        if rpkt is None or\
            not TCP in None:
            return None
        self.rcv_fin(rpkt)
        if rpkt[TCP].flags == self.get_flag_val("F") or\
            rpkt[TCP].flags == self.get_flag_val("FA") and\
            self.state == "ESTABLISHED":
            self.state = "CLOSED"
            return self.send_pkt( s=s, flags="FA")
        elif rpkt[TCP].flags == self.get_flag_val("F") or\
            rpkt[TCP].flags == self.get_flag_val("FA") and\
            self.state == "FIN_WAIT_1":
            self.state = "CLOSED"
            return self.send_pkt( s=s, flags="A")
        return (None, None)
    
    def rcv_seg_ans(self, rpkt, s):
        if rpkt is None or\
            not TCP in rpkt:
            return None
        rflags = rpkt[TCP].flags
        if rflags == self.get_flag_val("S"):
            return self.rcv_syn_ans(rpkt, s)
        elif rflags == self.get_flag_val("A"):
            # TODO this is only an ACK and 
            # ot could mean a number of things
            # this can not be answered automatically
            # yet
            return self.rcv_ack_ans(rpkt, s)
        elif rflags == self.get_flag_val("F") or\
            rflags == self.get_flag_val("FA"):
            return self.rcv_fin_ans(rpkt, s) 
        elif rflags == self.get_flag_val("SA"):
            return self.rcv_synack_ans(rpkt, s)
        elif rflags == self.get_flag_val("PA"):
            return self.rcv_pshack_ans(rpkt, s)
        
    def rcv_pshack_ans(self, rpkt, s=None):
        if rpkt is None or\
            not TCP in None:
            return None
        
        self.update_from_pkt(rpkt)
        
    def rcv_ack(self, rpkt):
        '''
        Update TCP SM based on rcv'd a ack packet.

        :param rpkt: IP/TCP pkt
        :type rpkt: scapy.Packet
        '''
        self.update_from_pkt(rpkt)
    
    def rcv_ack_ans(self, rpkt, s=None):
        self.rcv_ack(rpkt)
        return None
    
    def send_rcv_pkts(self, s, pkt):
        '''
        Send and recv packets.

        :param s: socket to send packet out on
        :type s: scapy.L3Socket
        :param pkt: IP/TCP pkt
        :type pkt: scapy.Packet

        :return: packet recieved from sending the pkt                
    
        :rtype: scapy.Packet
        '''
        result = self.quick_send(s, pkt)
        if len(result[0]) == 0:
            self.seg_record.append((pkt, None))
            return None
        rpkt = result[0][0][1]
        self.seg_record.append((pkt, rpkt))
        return rpkt
    
    # TCP state transitioning takes place here
    def state_closed(self, rpkt):
        self.state == "CLOSED"
        return   self.state
    
    def state_listen(self, rpkt, s=None):
        if TCP in rpkt and\
            rpkt[TCP].flags == self.get_flag_val("S"):
            self.state = "SYN_RCVD"
            self.move_state = self.state_syn_rcvd
            self.rcv_syn(rpkt)
            return self.state
        return self.state
    
    def state_syn_rcvd(self, rpkt, s=None):
        if TCP in rpkt and\
            rpkt[TCP].flags == self.get_flag_val("A"):
            self.state = "ESTABLISHED"
            self.move_state = self.state_established(rpkt, s)
            self.rcv_ack(rpkt, s)
            #self.send_synack(pkt, s)            

    def state_syn_sent(self, rpkt, s=None):
        if TCP in rpkt and\
            rpkt[TCP].flags == self.get_flag_val("A"):
            self.state = "ESTABLISHED"
            self.move_state = self.state_established
            return self.rcv_synack_ans(rpkt, s)
    
    def state_established(self, rpkt, s=None):
        if not TCP in rpkt:
            return None
        
        if rpkt[TCP].flags == self.get_flag_val("A"):
            return self.rcv_ack(rpkt)
        elif rpkt[TCP].flags == self.get_flag_val("PA"):
            return self.rcv_pshack(seg)
        elif rpkt[TCP].flags == self.get_flag_val("RA"):
            pass
            #return self.rcv_ack(seg)
        elif rpkt[TCP].flags == self.get_flag_val("F"):
            # TODO implement rcv_fin 
            self.state = "CLOSE_WAIT"
            self.move_state = self.state_close_wait
            # do not care about the return value for the 
            # ack of the fin, since the socket will close
            # on the remote end
            rpkt2, pay= self.send_pkt(self.get_base_pkt(), s=s,flags="A")
            return self.move_state(rpkt)
            #return self.rcv_fin_ans(seg)
        elif rpkt[TCP].flags == self.get_flag_val("FA"):
            return self.rcv_finack(seg)
    
    def state_close_wait(self, rpkt, s=None):
        if self.state == "CLOSE_WAIT":
            self.state = "LAST_ACK"
            self.move_state = self.state_last_ack
            rpkt, pay = self.send_pkt(rpkt, s, flags="F")
            return self.move_state(rpkt, s)
    
    def state_last_ack(self, rpkt, s=None):
        if self.state == "LAST_ACK" and\
            TCP in rpkt and\
            rpkt[TCP].flags == self.get_flag_val("A"):
            self.state = "CLOSED"
            self.move_state = self.state_closed 
        return False
    
    def state_closing(self, rpkt, s=None):  
        if self.state == "CLOSING" and\
            TCP in rpkt and\
            rpkt[TCP].flags == self.get_flag_val("A"):
            self.state == "TIME_WAIT"
            self.move_state = self.state_time_wait
            return True
        return False
        
    def state_time_wait(self, rpkt, s=None):
        if self.state == "TIME_WAIT":
            # dont care about cheking rpkt from for an ack
            # from the fin in the closing state
            self.state = "CLOSED"
            self.move_state = self.state_closed
            return True
        return False
    
    def state_fin_wait_1(self, rpkt, s=None):
        if self.state != "FIN_WAIT_1":
            return False
        if TCP in rpkt and\
            rpkt[TCP].flage == self.get_flag_val("F"):
            self.state = "FIN_WAIT_2"
            self.move_state = self.state_fin_wait_2
            return self.move_state(rpkt)
        
        if TCP in rpkt and\
            rpkt[TCP].flags == self.get_flag_val("F"):
            # TODO implement rcv_fin_ans
            #rpkt = self.rcv_fin(rpkt, s)
            self.move_state = self.state_closing
            self.state = "CLOSING"
            return self.move_state(rpkt, s)

    def state_fin_wait_1(self, rpkt, s=None):
        if self.state == "FIN_WAIT_1" and\
            TCP in rpkt and\
            rpkt[TCP].flage == self.get_flag_val("A"):
            self.state = "TIME_WAIT"
            self.move_state = self.state_fin_wait_2
            return self.move_state(rpkt)
        
    def rcv_seg(self, rpkt):
        self.move_state(rpkt)
        
    def establish_connection(self, pkt, s=None):
        '''
        Send and recv packets.

        :param pkt: IP/TCP pkt
        :type pkt: scapy.Packet
        :param s: socket to send packet out on
        :type s: scapy.L3Socket

        :return: successful connection established,
                 packet received from sending the pkt
        :rtype: boolean, scapy.Packet
        '''
        print ("Preparing to establish a TCP Connection..")
        self.get_socket(s)
        s = None
        print ("Prepping and Sending Syn Segment")
        rpkt, pay = self.send_pkt(pkt, self.sock, flags="S")
        
        if rpkt is None or\
            not self.check_flags(rpkt[TCP], "SA"):
            return False, rpkt 
        self.state = "SYN_SENT"
        rpkt = self.rcv_synack_ans(rpkt, s)
        return True, rpkt
    
    def listen(self, lport, s=None, timeout=None):
        """
        Listen for a connection attempt.

        :param lport: port to look for in the syn packet
        :type lport:  port to listen for
        :param s: scapy socket to listen on, if none one is initialized
        :type s:  scapy.L2Socket
        :param timeout: stop sniffing after a given time (default: None)
        :type timeout: length of time to listen for

        :return: successful connection established,
                 packet received from sending the pkt                
    
        :rtype: boolean, scapy.Packet
        """
        print ("Preparing to listen for a TCP Connection..")
        self.get_socket(s)
        s = None

        print ("Listening for a connection request")
        rpkt = self.listen_for_syn(lport, timeout=timeout)
        rpkt = self.rcv_syn_ans(rpkt)
        if not rpkt is None:
            return True, rpkt
        return False, rpkt
    
    def simple_send_data(self, seg, payload=None):
        """
        Send data, payload, to the remote host using the TCP state machine.
        The data is contained in payload, and any payload that can not be sent
        is returned back to the user.
        
        :param seg: seg contains the data payload
        :type seg: scapy.TCP
        :param payload: seg data to send
        :type payload: string
        
        :return: successfully sent all data, unsent data
        :rtype: (boolean, string)
        """
        p = ""
        success = False
        if not payload is None:
            p = payload
            payload = None
        elif payload is None and\
            not seg.payload is None:
            p = str(seg.payload)
            seg.payload = None
        
        while 1:
            seg, p = self.SND.update_seg(seg, p)
            if seg is None:
                success = False
                break
        
        return success, p
    
    def flush_rcv_socket(self, sock):
        '''
        Flush out all the packets from a socket.

        :param sock: socket to read all data out of
        :type sock: scapy.SuperSocket

        :return: list of all the packets read out of the socket
        :rtype: list 
        '''
        
        pkts = []
        while 1:
            pkt = sock.recv(MTU)
            if pkt is None: break
            pkts.append(pkt)
        return pkts
            
    
    def listen_for_syn(self, lport, s=None, timeout=None, sel_timeout=.1):
        """
        Listen for a Syn Packet (based on sniff).

        :param lport: port to look for in the syn packet
        :type lport:  port to listen for
        :param s: scapy socket to listen on, if none one is initialized
        :type s:  scapy.L3Socket
        :param timeout: stop sniffing after a given time (default: None)
        :type timeout: int
        :param sel_timeout: select timeout period
        :type sel_timeout: int
        """
        self.get_socket(s)
        s = None
            
        syn_filter = lambda pkt: not pkt is None and\
                                 TCP in pkt and\
                                 pkt[TCP].flags == self.get_flag_val("S") and\
                                 pkt[TCP].dport== lport
        
        if timeout is not None:
            stoptime = time.time()+timeout
        remain = None
        pkts = []
        p = self.flush_rcv_socket(self.sock)
        while 1:
            try:
                if timeout is not None:
                    remain = stoptime-time.time()
                    if remain <= 0:
                        break
                sel = select([self.sock],[],[], .1)
                if not sel[0] is None:
                    p = self.sock.recv(MTU)
                    if p is None:
                        continue
                    if syn_filter(p):
                        return p
            except KeyboardInterrupt:
                break
        return None
    
    def quick_send(self, sock, pkt, timeout=4, inter=0, verbose=None,chainCC=0, retry=0, multi=0):
        '''
        Quick send is just a wrapper around scapy sndrcv(...)
        Check the code or docs for keywords and other stuff, but we
        simply pass in a packet and a socket.
        
        :param sock: initialized socket for sending packet data
        :type sock: scapy.L3socket
        :param pkt: packet to send
        :type pkt: scapy.Packet 
        '''
        return sndrcv(sock, pkt, timeout, inter, verbose, chainCC, retry, multi)        
    
    def init_socket(self, iface=None, filter=None, nofilter=0):
        print ("Initializing Socket")
        return self.init_L3socket(filter=filter, nofilter=nofilter,iface=iface)
    
    def init_L3socket(self, iface=None, filter=None, nofilter=0):
        print ("Initializing Socket")
        self.sock = conf.L3socket(filter=filter, nofilter=nofilter,iface=iface)
        print(("The following socket was initialized", str(socket)))
        return self.sock
    
    def init_L2socket(self, iface=None, filter=None, nofilter=0):
        print ("Initializing Socket")
        self.sock = conf.L2socket(filter=filter, nofilter=nofilter,iface=iface)
        print(("The following socket was initialized", str(socket)))
        return self.sock
