#!/usr/bin/python3

# Copyright (C) 2024 strangebit
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from packets import TCPPacket, IPv4Packet

"""
Comparisions made when processing ACK packets:

SND.UNA oldest unacknowledged sequence number (everything else prior to this sequence number was acknowledged)
SND.NXT next sequence number to be sent
SEG.ACK Acknowledgement from the receiving TCP (next sequence number expected by the receiver)
SEG.SEQ First sequence number of the segment
SEG.SEQ + SEG.LEN - 1 last sequence number of a segment

New acknowledgement sequence (acceptable ACK) 

SND.UNA < SEQ.ACK <= SND.NXT

A segment in the retransmission queue is fully acknowledged if the sum of its sequence number and length is less 
than or equal to the acknoledgement value in the incomming segment.
That is remove all packets from the retransmission queue if SEQ + LEN <= ACK

When data is recieved the following comparisons are needed:

RCV.NXT = next sequence number expected on an incomming segments, and is
the left or lower edge of the receive window
RCV.NEXT+RCV.WND-1 = last sequence number expected on an incomming segment, 
and is th right or upper edge of the receive window
SEG.SEQ = first sequence number occupied by the incomming segment
SEG.SEQ + SEG.LEN-1 = last sequence number occupied by the incomming segment

The segment has a valid receive sequecet number if:
1) RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND
or
2) RCV.NXT <= SEG.SEQ + SEG.LEN - 1 < RCV.NXT + RCV.WND

More specific (valid sequence number):
Segment Recieve Test
Length  Window  
 0       0       SEG.SEQ = RCV.NXT
 0       >0      RCV.NXT <= SEG.SEQ < RCV.NXT + RCV.WND
 >0      0       not acceptable
 >0      >0      RCV.NXT <= SEG.SEQ + SEG.LEN - 1 < RCV.NXT + RCV.WND
 Whem window is 0 not segments are acceptable excep ACKs

"""

ALPHA = 0.8
BETA = 1.3

# Threading
import threading
# Sockets
import socket
import select
# Timing
from time import time, sleep
from config import config

MTU = config.get('MTU', 1500);

class TransmissionControlBlock():
    def __init__(self):
        self.snd_una = 0
        self.snd_nxt = 0
        self.snd_wnd = 0
        self.snd_up = 0
        self.snd_wl1 = 0
        self.snd_wl2 = 0
        self.iss = 0
        self.rcv_nxt = 0
        self.rcv_wnd = 0
        self.rcv_up = 0
        self.irs = 0
        self.iw = 0
        self.cwnd = 0
        self.rwnd = 0
        self.lw = 0
        self.rw = 0
    def snd_una(self, value = None):
        if value:
            self.snd_una = value
        else:
            return self.snd_una
    def snd_nxt(self, value = None):
        if value:
            self.snd_nxt = value
        else:
            return self.snd_nxt
    def snd_wnd(self, value = None):
        if value:
            self.snd_wnd = value
        else:
            return self.snd_wnd
    def snd_up(self, value = None):
        if value:
            self.snd_up = value
        else:
            return self.snd_up
    def snd_wl1(self, value = None):
        if value:
            self.snd_wl1 = value
        else:
            return self.snd_wl1
    def snd_wl2(self, value = None):
        if value:
            self.snd_wl2 = value
        else:
            return self.snd_wl2
    def iss(self, value = None):
        if value:
            self.iss = value
        else:
            return self.iss
    def rcv_nxt(self, value = None):
        if value:
            self.rcv_nxt = value
        else:
            return self.rcv_nxt
    def rcv_wnd(self, value = None):
        if value:
            self.rcv_wnd = value
        else:
            return self.rcv_wnd
    def rcv_up(self, value = None):
        if value:
            self.rcv_up = value
        else:
            return self.rcv_up
    def irs(self, value = None):
        if value:
            self.irs = value
        else:
            return self.irs

class TCPStates():
    def __init__(self):
        self.LISTEN = 0
        self.SYN_SENT = 1
        self.SYN_RECEIVED = 2
        self.ESTABLISHED = 3
        self.FIN_WAIT_1 = 4
        self.FIN_WAIT_2 = 5
        self.CLOSE_WAIT = 6
        self.CLOSING = 7
        self.LAST_ACK = 8
        self.TIME_WAIT = 9
        self.CLOSED = 10

class TCP():
    def __init__(self):
        self.tcb = TransmissionControlBlock()
        self.states = TCPStates()
        self.send_queue = {}
        self.receive_queue = {}
        self.received_data = bytearray([])
        self.data_to_send = bytearray([])
        self.last_send_sequence = 0
        self.last_recv_sequence = 0
        self.state = TCPStates().CLOSED

    def __noop__(self):
        sleep(0.1)

    def __recv__(self):
        while True:
            buf = bytearray(self.socket.recv(MTU));
            if self.state == self.states.CLOSED:
                continue;
            if self.state == self.states.CLOSED:
                continue;

    def __send__(self):
        while True:
            if self.state == self.states.CLOSED:
                pass
            self.__noop__()

    def open(self, src, dst, src_port, dst_port, listen = False):
        # creates a raw socket and binds it to the source address
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.socket.bind((src, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);
        
        self.recv_thread = threading.Thread(target = self.__recv__, args = (), daemon = True);
        self.send_thread = threading.Thread(target = self.__send__, args = (), daemon = True);

        self.recv_thread.start()
        self.send_thread.start()
        
        self.tcp = TransmissionControlBlock()
        self.states = TCPStates()
        if listen:
            self.state = self.states.LISTEN
        else:
            self.state = self.states.CLOSED;
        
    def send(self, data):
        self.data_to_send += bytearray(data)
    def receive(self, len):
        if len(self.received_data) >= len:
            buf = self.received_data[:len]
            self.received_data = self.received_data[len:]
            return self.buf
    def close(self):
        # Send FIN packet
        pass
    def abort(self):
        pass
    def status(self):
        pass
    
