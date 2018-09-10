"""

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

description: broken code
        
"""
from scapy.all import *
from random import randint

class Snd:
    '''
    TCP SND object.  Reference RFC 793.  TCP not fully implemented.
    '''
    
    def __init__(self):
        self.UNA = randint(0, 65535) # send unacknowledged
        self.NXT = self.UNA + 1 # send next
        self.WND = 8192 # send window
        self.UP = 0 # send urgent pointer
        self.WL1 = 0 # segment sequence number used for last window update
        self.WL2 = 0 # segment acknowledgment number used for last window update
        self.ISS = self.UNA + 1# initial send sequence number
    
    
    def init_from_rcv_seg(self, seg):
        '''
        Set the default seq number based on a segment.
        '''
        self.ISS = seg.ack
        self.NXT = seg.ack
        self.UNA = self.NXT - 1
        self.WND = seg.window
        self.WL2 = seg.seq
        self.WL1 = seg.ack
    
    def init_from_seg(self, seg):
        self.init_from_snd_seg(seg)
    
    def init_from_snd_seg(self, seg):
        '''
        Set the default seq number based on a segment.
        '''
        self.ISS = seg.seq
        self.NXT = seg.seq
        self.UNA = self.NXT -1 
        self.WND = seg.window
        self.WL2 = seg.ack
        self.WL1 = seg.seq

    
    def get_nxt_seq(self):
        '''
        Get the next valid seq number.

        :return: next sequence number
        :rtype: int
        '''
        return self.NXT
    
    def can_send_data(self):
        '''
        Determine if data can be sent at this time by checking the current
        window.

        :return: data can be sent
        :rtype: boolean
            
        '''
        if self.UNA > self.NXT:
            return ((self.NXT + MAX) - self.UNA) % MAX < WND
        return (self.NXT - self.UNA) < WND
    
    def is_acceptable_ack(self, ack):
        '''
        Check the ack to see if it is valid.

        :return: ack is valid
        :rtype: boolean
        '''
        print (self)
        print((self.UNA + self.WND, self.UNA, (self.UNA + self.WND) % MAX))
         
        UPP = (self.UNA + self.WND) % MAX
        LOW = self.UNA
        is_valid = False
        if LOW <= UPP:
            is_valid = LOW <= ack < UPP
            print(("LOW: %d < ack: %d < UPP: %d"%(LOW, ack, UPP)))    
        else:
            if ack < LOW:
                is_valid = LOW <= ack + MAX < UPP + MAX
                print(("LOW: %d < ack: %d < UPP: %d"%(LOW,ack+MAX, UPP+MAX)))
                
            else:
                is_valid = LOW <= ack < UPP + MAX
                print (("LOW: %d < ack: %d < UPP: %d"%(LOW, ack,UPP+MAX)))
	return is_valid
    
    def update_una(self, ack):
        '''
        Update the un-acked segments to the current ack number.

        :param ack: current ack number
        :type ack: int

        :return: ack is valid
        :rtype: boolean
        '''
        self.UNA = (self.UNA + ack) % MAX
    
    def rcv_seg(self, seg):
        '''
        Check the current segment to see if its valid, then 
        update the sliding window (e.g. NXT & UNA)

        :param seg: current segment
        :type seg: scapy.TCP

        :return: state successfully updated
        :rtype: boolean
        '''
        
        print(("Segment ack: ",self.is_acceptable_ack(seg.ack), "\n",repr(seg)))
        if self.is_acceptable_ack(seg.ack):
            ack_wnd = self.get_ack_wnd(seg.ack)
            self.update_una(ack_wnd)
            return True
        return False
    
    def update_from_seg(self, pkt):
        '''
        Check the current pkt to see if its valid, then update the sliding
        window (e.g. NXT & UNA) if the ack is valid.

        :param pkt: packet to update TCP SND state from 
        :type pkt: scapy.Packet

        :return: state successfully updated
        :rtype: boolean
        '''
        if not TCP in pkt: return False
        return self.rcv_seg(pkt[TCP])
        
    def update_seg(self, seg, p_load=None):
        '''
        Update the segment in accordance to the sliding window Returns a tuple
        of the segment and any unused payload.  If a valid segment CAN NOT be
        sent then the returned seg is None.

        :param seg: segment to update 
        :type seg: scapy.Packet
        :param p_load: payload to include in the packet
        :type p_load: string

        :return: (segment if one was created, Otherwise None, unused payload data)
        :rtype: tuple
        '''
        payload = ""
        #seg.show()
        if not p_load is None:
            payload = p_load
            p_load = None
        else:
            payload = str(seg.payload)
        
        wnd_sz = self.get_current_wnd_sz()
        print(("Calculated a wnd_sz of %x" % wnd_sz))
        if wnd_sz <= 0:
            return None, payload
        
        
        data_len = self.get_payload_len(payload, wnd_sz)
        seg.seq = self.NXT
        self.update_nxt(data_len + 1)
        if payload != '':
            seg.payload = payload
        if len(payload) > data_len:
            seg.payload = payload[:data_len]
            return seg, payload[data_len:]
        return seg, ""

    def force_update_seg(self, seg, p_load=None):
        '''
        Update the segment in accordance to the sliding window Returns a tuple
        of the segment and any unused payload.  If a valid segment CAN NOT be
        sent then the returned seg is None.

        :param seg: segment to update 
        :type seg: scapy.Packet
        :param p_load: payload to include in the packet
        :type p_load: string

        :return: (segment if one was created, Otherwise None, unused payload
                 data)
        :rtype: tuple
        '''
        payload = ""
        if not p_load is None:
            payload = p_load
            p_load = None
        else:
            payload = str(seg.payload)
        wnd_sz = self.get_current_wnd_sz()
        print(("Calculated a wnd_sz of %x" % wnd_sz))
        
        data_len = self.get_payload_len(payload, wnd_sz)
        seg.seq = self.NXT
        self.update_nxt(data_len + 1)
        if payload != '':
            seg.payload = payload
        if len(payload) > data_len:
            seg.payload = payload[:data_len]
            return seg, payload[data_len:]
        return seg, ""

    
    def get_payload_len(self, payload, rem_sz=None):
        '''
        Get the packet length with the payload.

        :param payload: payload to be sent in the segment
        :type payload: string
        :param rem_sz: remaining size in the sliding window
        :type rem_sz: int or None

        :return: the value of the next sequence number after the segment is
                 sent
        :rtype: int
        '''
        wnd_sz = 0
        if not rem_sz is None:
            wnd_sz = rem_sz
            rem_sz = None
        else: 
            wnd_sz = self.get_current_wnd_sz()
        if len(payload) > wnd_sz:
            return wnd_sz
        return len(payload)
        
    def get_current_wnd_sz(self):
        '''
        Get the remaining window size for sending packet data.

        :return: remaining data that can be sent in the window
        :rtype: int 
        '''
        wnd_used = abs(self.NXT - self.UNA)
        if self.UNA > self.NXT:
            wnd_used = abs((self.NXT + MAX) - self.UNA) % MAX
        return self.WND - wnd_used

    def get_ack_wnd(self, ack):
        '''
        Get the window that corresponds to the ack number.

        :param ack: ack to obtain the update window from
        :type ack: int

        :return: window of data to be ack'ed
        :rtype: int
        '''
        ack_wnd = abs(self.UNA - ack)
        if ack >= self.UNA:
            ack_wnd = abs(self.UNA + MAX - ack) % MAX
        return ack_wnd
    
    def set_wnd(self, wnd):
        '''
        Set the sliding window size.

        :param wnd: new sliding window size
        :type wnd: int
        '''
        self.WND = wnd
            
    def update_nxt(self, incr):
        '''
        Update the NXT valid seq number after data after prep'ing a segment.

        :param incr:  increment the NXT by the previous segment size
        :type incr: int
        '''
        self.NXT = (self.NXT + incr) % MAX
    
    def __str__(self):
        s = "SND Object values\n"
        s += "UNA: %d \n"%self.UNA 
        s += "NXT: %d \n"%self.NXT 
        s += "WND: %d \n"%self.WND 
        s += "UP: %d \n"%self.UP 
        s += "WL1: %d \n"%self.WL1 
        s += "WL2: %d \n"%self.WL2 
        s += "ISS: %d \n"%self.ISS 
        return s