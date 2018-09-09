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

class Rcv:
    '''
    TCP RCV object.  Reference RFC 793.  TCP not fully implemented.
    '''

    def __init__(self):
        self.NXT = randint(0, 65535) # receive next
        self.WND = 0 # receive window
        self.UP = 0 # receive urgent pointer
        self.IRS = self.NXT # initial receive sequence number
        self.rcvd_segs = {}
    
    def init_from_seg(self, seg):
        '''
        Set the default seq number based on a rcvd syn-ack segment.
        '''
        self.init_from_rcv_seg(seg)

    def init_from_snd_seg(self, seg):
        '''
        Set the default seq number based on a rcvd syn-ack segment.
        '''
        self.WND = seg.window
        self.IRS = seg.ack
        self.NXT = (seg.ack) % MAX
    
    def init_from_rcv_seg(self, seg):
        '''
        Set the default seq number based on a rcvd syn-ack segment.
        '''
        self.WND = seg.window
        self.IRS = seg.seq
        self.NXT = (seg.seq) % MAX

    def init_from_seg(self, seg):
        self.init_from_rcv_seg(seg)

    def update_nxt(self, incr):
        '''
        Update the NXT valid ack number after sending an ack.

        :param incr:  Increment the NXT by the previous segment size.
        :type incr: int
        '''
        self.NXT = (self.NXT + incr) % MAX
    
    def rcv_seg(self, seg):
        '''
        Check the current segment to see if its valid, then 
        update the sliding window (e.g. NXT)

        :param seg: current segment
        :type seg: scapy.TCP

        :return: state successfully updated
        :rtype: boolean
        '''
        if self.is_acceptable_seq(seg.seq, len(seg.payload)+1):
            self.rcvd_segs[seg.seq] = seg
            if self.NXT != seg.seq:
                return False
            return self.accumulate_acks()
        return False
        
    def accumulate_acks(self):
        '''
        Accumulate saved segments, this will need to be changed if RT Timers
        are used.

        :return: updated ack window
        :rtype: boolean
        '''
        rcvd_seqs = self.rcvd_segs.keys()
        rcvd_seqs.sort()
        flag = False
        for i in rcvd_seqs:
            seg = self.rcvd_segs[i]
            if seg.seq == self.NXT:
                incr = len(str(seg.payload)) + 1
                self.update_nxt(incr)
                del self.rcvd_segs[i]
                flag = True
            else:
                break
        return flag
    
    def update_seg(self, seg):
        '''
        Update the segment in accordance to the sliding window
        Returns a tuple of the segment and any unused payload.  If
        a valid segment CAN NOT be sent then the returned seg is None.

        :param seg: segment to update 
        :type seg: scapy.Packet

        :return: (segment if one was created, Otherwise None, unused payload data)
        :rtype: tuple
        '''
        seg.ack = self.get_nxt_ack()
        
        return seg, None
    
    def get_last_ack(self):
        '''
        Return current last ack value sent.

        :return: current ack number or seq number we are waiting for  
        :rtype: int
        '''
        return self.NXT - 1
    
    def get_nxt_ack(self):
        '''
        Return current ack Number.

        :return: current ack number or seq number we are waiting for  
        :rtype: int
        '''
        return self.NXT

        
    def update_from_seg(self, pkt):
        '''
        Check the current pkt to see if its valid, then 
        update the sliding window (e.g. NXT & UNA) if the 
        ack is valid.

        :param pkt: packet to update TCP SND state from 
        :type pkt: scapy.Packet

        :return: state successfully updated
        :rtype: boolean
        '''
        
        if not TCP in pkt: return
        self.rcv_seg(pkt[TCP])
            
    def set_wnd(self, wnd):
        '''
        Set the TCP window.

        :param wnd: new window to set the RCV too
        :type wnd: int
        '''
        self.WND = wnd

    def is_acceptable_seq(self, seq, seg_sz):
        '''
        Check the seq to see if it is valid.

        :return: seq is valid
        :rtype: boolean
        '''
        UPP = (self.NXT + self.WND) % MAX
        LOW = self.NXT % MAX
        is_valid = False
        print ("seq: %d LOW: %d UPP: %d"%(seq, LOW, UPP))
        if LOW <= UPP:
            is_valid = LOW <= seq + seg_sz < UPP
            print ("LOW: %d  <= seq + seg_sz: %d  < UPP: %d == %s"%(LOW, seq+seg_sz, UPP, str(is_valid)))
        else:
            if seq < LOW:
                is_valid = LOW <= seq + seg_sz + MAX < UPP + MAX
                print ("LOW: %d  <= seq + seg_sz + MAX: %d  < UPP: %d == %s"%(LOW, seq+seg_sz+MAX, UPP+MAX, str(is_valid)))
            else:
                is_valid = LOW <= seq + seg_sz < UPP + MAX
                print ("LOW: %d  <= seq + seg_sz: %d  < UPP: %d == %s"%(LOW, seq+seg_sz, UPP+MAX, str(is_valid)))
        return is_valid
    
    def __str__(self):
        s = "RCV Object values\n"
        s += "NXT: %d \n"%self.NXT 
        s += "WND: %d \n"%self.WND 
        s += "UP: %d \n"%self.UP 
        s += "IRS: %d \n"%self.IRS
        f = self.rcvd_segs.keys()
        f.sort()
        k = lambda num: str(num)
        s += "rcvd_segs: %s \n"%",".join(map(k, f)) 
        return s