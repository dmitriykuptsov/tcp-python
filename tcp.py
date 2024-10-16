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

ALPHA = 0.8
BETA = 1.3

import traceback

# Threading
import threading
# Sockets
import socket
import select
# Timing
import time
from time import sleep, time
from config import config
# Utils 
from utils import Checksum, Misc, TCPUtils
# Packets 
import packets
# Trace back 
import traceback

MTU = config.get('MTU', 1500);
MSS = config.get('MSS', 536);
MSL = config.get('MSL', 4800)
UBOUND = 60
LBOUND = 1

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
        self.cwnd = MSS
        self.rwnd = 0
        self.lw = 0
        self.rw = 0
        self.sport = 0
        self.dport = 0
        self.u_timeout = time() + 1200
        self.tw_timeout = time() + 2 * MSL

    def time_wait_timeout(self, value = None):
        if value:
            self.tw_timeout = value
        else:
            return self.tw_timeout

    def user_timeout(self, value = None):
        if value:
            self.u_timeout = value
        else:
            return self.u_timeout
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
        self.tcb = None;
        self.states = TCPStates()
        self.send_queue = {}
        self.receive_queue = {}
        self.received_data = bytearray([])
        self.data_to_send = bytearray([])
        self.last_send_sequence = 0
        self.last_recv_sequence = 0
        self.srtt = 1
        self.rto = 1
        self.passive = False
        self.state = TCPStates().CLOSED
        self.ssthresh = 2 * MSS
        self.bytes_in_flight = 0
        self.cwnd = MSS

    def __noop__(self):
        sleep(0.1)

    def __maintenance__(self):
        while True:
            if self.tcb and self.tcb.user_timeout() <= time():
                self.state = self.states.CLOSED
                self.tcb = None
                #print("-----------------TIMEOUT-----------------")
                continue
            if self.state == self.states.TIME_WAIT:
                if self.tcb.time_wait_timeout() <= time():
                    #print("Connection was closed due to timeout")
                    self.state = self.states.CLOSED
                    self.tcb = None
            elif self.state == self.states.ESTABLISHED:
                currenttime = time()
                seqs = list(self.send_queue.keys())
                for seq in seqs:
                    # Retransmit everything in the queue
                    try:
                        timestamp, rto, ipv4packet = self.send_queue.get(seq, None)
                    except:
                        continue
                    if currenttime > rto:
                        self.ssthresh = max (self.bytes_in_flight / 2, 2*MSS)
                        self.tcb.cwnd = MSS;
                        #tcp_packet = TCPPacket(ipv4packet.get_payload())
                        #tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        self.send_queue[seq] = (time(), time() + self.rto, ipv4packet)
                        #print("Retransmitting the packet...")
                        #tcp_packet = TCPPacket(ipv4packet.get_payload())
                        #print("SEND SEQUENCE...... %s %s" % (tcp_packet.get_sequence_number(), seq))
                seqs = list(self.receive_queue.keys())
                seqs.sort()
                if len(seqs) == 1:
                    if seqs[0] < self.last_recv_sequence:
                        del self.receive_queue[seqs[0]]
                        continue
                    timestamp, ipv4packet = self.receive_queue.get(seqs[0], None)
                    tcp_packet = TCPPacket(ipv4packet.get_payload())
                    self.received_data += tcp_packet.get_data()
                    self.last_recv_sequence += len(tcp_packet.get_data())
                    #print(self.bytes_in_flight)
                    #print(len(tcp_packet.get_data()))
                    #self.bytes_in_flight -= len(tcp_packet.get_data())
                    del self.receive_queue[seqs[0]]
                    #print("Removing the packet from the receive queue")
                else:
                    for i in range(0, len(seqs) - 1):
                        if seqs[i] < self.last_recv_sequence:
                            del self.receive_queue[seqs[i]]
                            continue
                        timestamp, ipv4packet = self.receive_queue.get(seqs[i], None)
                        if not timestamp:
                            continue 
                        tcp_packet = TCPPacket(ipv4packet.get_payload())
                        if seqs[i + 1] - seqs[i] - len(tcp_packet.get_data()) == 0:
                            self.received_data += tcp_packet.get_data()
                            self.last_recv_sequence += len(tcp_packet.get_data())
                            #print(self.bytes_in_flight)
                            #print(len(tcp_packet.get_data()))
                            #self.bytes_in_flight -= len(tcp_packet.get_data())
                            del self.receive_queue[seqs[i]]
                            #print("Removing the packet from the receive queue 2")
                            continue
                        else:
                            break
            if self.state != self.states.CLOSED and self.tcb:
                #print(time())
                #print(time() + 1200)
                self.tcb.user_timeout(time() + 1200)

            if self.state != self.states.CLOSED and self.tcb:
                self.tcb.time_wait_timeout(time() + 2 * MSL)

    def __recv__(self):
        while True:
            try:
                #print("GOT PACKET")
                buf = bytearray(self.socket.recv(MTU));
                ipv4packet = IPv4Packet(buf)
                if ipv4packet.get_destination_address() != self.src_bytes:
                    continue
                tcp_packet = TCPPacket(ipv4packet.get_payload())
                if self.state != self.states.LISTEN:    
                    if tcp_packet.get_source_port() != self.dport and tcp_packet.get_destination_port() != self.sport:
                        continue
                    checksum = tcp_packet.get_checksum()
                    tcp_packet.set_checksum(0)
                    pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                    if (Checksum.checksum(pseudo_header + tcp_packet.get_buffer()) & 0xFFFF) != (checksum & 0xFFFF):
                        #print("Invalid checksum detected")
                        #continue
                        pass
                else:
                    if tcp_packet.get_destination_port() != self.sport:
                        continue
                #print("STARTING MAIN LOOP")
                #print(self.state)
                if self.state == self.states.CLOSED:
                    continue
                elif self.state == self.states.CLOSE_WAIT:
                    # First check
                    not_acceptable = False
                    if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                        ##print("Window is zero and the package is > 0")
                        not_acceptable = True

                    if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                        if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                            ##print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                        if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                            ##print("Window > 0 plen=0 but the sequance is out of window")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                        if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                                (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                                self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                            ##print("W>0 plen>0 but the rcv_nxt <= seq < ")
                            not_acceptable = True
                    
                    if not not_acceptable:
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        continue
                        continue
                    
                    # Second check

                    if tcp_packet.get_rst_bit():
                        # Clean all queues
                        self.state = self.states.CLOSED
                        ##print("Moving to close state CLOSE WAIT 1")
                        self.tcb = None

                    # Third check
                    if tcp_packet.get_syn_bit():
                        # Send reset packet
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_rst_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        # Clean all queues
                        self.state = self.states.CLOSED
                        self.receive_queue = {}
                        self.send_queue = {}
                        ##print("Moving to close state CLOSE WAIT 2")
                        self.tcb = None
                        continue

                    # Fifth check
                    if not tcp_packet.get_ack_bit():
                        # Drop the packet and return
                        continue

                    if tcp_packet.get_ack_bit():
                        #print("GOT ACK... %s" % tcp_packet.get_acknowledgment_number())
                        if self.tcb.snd_una < tcp_packet.get_acknowledgment_number() and tcp_packet.get_acknowledgment_number() <= self.tcb.snd_nxt:
                            acked_bytes = tcp_packet.get_acknowledgment_number() - self.tcb.snd_una - 1
                            self.tcb.snd_una = tcp_packet.get_acknowledgment_number()
                            #print("SETTING UNA ---------------- %s" % self.tcb.snd_una)
                            # Remove the packets that have sequnce <= self.tcb.snd_una
                            stimestamp, rto, packet = self.send_queue[tcp_packet.get_acknowledgment_number()]
                            rtimestamp = time()
                            rtt = rtimestamp - stimestamp
                            self.srtt = (ALPHA * rtt) + ((1 - ALPHA) * rtt)
                            self.rto = min(UBOUND, max(LBOUND,(BETA * self.srtt)))
                            
                            old_tcp_packet = TCPPacket(packet.get_payload())
                            #self.bytes_in_flight -= acked_bytes #len(old_tcp_packet.get_data())

                            seqs = list(self.send_queue.keys())
                            for seq in seqs:
                                if seq <= self.tcb.snd_una:
                                    
                                    del self.send_queue[seq]
                            
                            #print("REMOVING PACKETS FROM THE SEND QUEUE")

                            if self.tcb.cwnd < self.ssthresh:
                                self.tcb.cwnd += MSS
                            else:
                                self.tcb.cwnd += MSS * MSS / self.tcb.cwnd
                                
                            if self.tcb.snd_wl1 < tcp_packet.get_sequence_number() or \
                                (self.tcb.snd_wl1 == tcp_packet.get_sequence_number() and \
                                self.tcb.snd_wl2 <= tcp_packet.get_acknowledgment_number()):
                                self.tcb.snd_wnd = tcp_packet.get_window()
                                self.tcb.snd_wl1 = tcp_packet.get_sequence_number()
                                self.tcb.snd_wl2 = tcp_packet.get_acknowledgment_number()
                        if tcp_packet.get_acknowledgment_number() > self.tcb.snd_nxt:
                            # Send ACK and drop the packet
                            #print("ACK is not acknowledging anything... sending ACK in response")
                            continue
                        if self.tcb.snd_una > tcp_packet.get_acknowledgment_number():
                            # Duplicate
                            #print("DUPLICATE.....")
                            continue
                elif self.state == self.states.TIME_WAIT:
                    # First check
                    not_acceptable = False
                    if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                        #print("Window is zero and the package is > 0")
                        not_acceptable = True

                    if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                        if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                            #print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                        if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                            #print("Window > 0 plen=0 but the sequance is out of window")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                        if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                                (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                                self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                            #print("W>0 plen>0 but the rcv_nxt <= seq < ")
                            not_acceptable = True
                    if not not_acceptable:
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        continue

                    # Second check

                    if tcp_packet.get_rst_bit():
                        self.state = self.states.CLOSED
                        self.tcb = None
                        #print("Moving to close state TIME WAIT")
                        continue

                    # Third check
                    if tcp_packet.get_syn_bit():
                        # Send reset packet
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_rst_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        # Clean all queues
                        self.state = self.states.CLOSED
                        self.receive_queue = {}
                        self.send_queue = {}
                        ##print("Moving to close state CLOSE WAIT 2")
                        self.tcb = None
                        continue
                        #print("Moving to close state TIME WAIT 2")

                    # Fourth check
                    if tcp_packet.get_fin_bit():
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        continue

                    # Eigth check

                    """
                    Restart the 2 MSL time-wait timeout.
                    """
                elif self.state == self.states.LAST_ACK:
                    # First check
                    #print("GOT PACKET FROM THE OTHER SIDE")
                    not_acceptable = False
                    if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                        #print("Window is zero and the package is > 0")
                        not_acceptable = True

                    if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                        if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                            #print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                        if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                            #print("Window > 0 plen=0 but the sequance is out of window")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                        if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                                (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                                self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                            #print("W>0 plen>0 but the rcv_nxt <= seq < ")
                            not_acceptable = True
                        
                    if not_acceptable:
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        continue
                    
                    # Second check

                    if tcp_packet.get_rst_bit():
                        self.state = self.states.CLOSED
                        self.tcb = None
                        #print("Moving to close state LAST ACK 1")
                        continue

                    # Third check
                    if tcp_packet.get_syn_bit():
                        # Send reset packet
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_rst_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        # Clean all queues
                        self.state = self.states.CLOSED
                        self.receive_queue = {}
                        self.send_queue = {}
                        ##print("Moving to close state CLOSE WAIT 2")
                        self.tcb = None
                        continue                  
                elif self.state == self.states.CLOSING:
                    # First check
                    #print("GOT PACKET FROM THE OTHER SIDE")
                    not_acceptable = False
                    if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                        #print("Window is zero and the package is > 0")
                        not_acceptable = True

                    if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                        if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                            #print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                        if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                            #print("Window > 0 plen=0 but the sequance is out of window")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                        if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                                (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                                self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                            #print("W>0 plen>0 but the rcv_nxt <= seq < ")
                            not_acceptable = True
                        
                    if not_acceptable:
                        #print("Not acceptable data received")
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        continue
                    
                    # Second check
                    if tcp_packet.get_rst_bit():
                        # Clean all queues
                        self.state = self.states.CLOSED
                        self.tcb = None

                    # Third check
                    if tcp_packet.get_syn_bit():
                        # Send reset packet
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_rst_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        # Clean all queues
                        self.state = self.states.CLOSED
                        self.receive_queue = {}
                        self.send_queue = {}
                        ##print("Moving to close state CLOSE WAIT 2")
                        self.tcb = None
                        continue

                    # Fifth check
                    if not tcp_packet.get_ack_bit():
                        # Drop the packet and return
                        continue
                    

                    if tcp_packet.get_ack_bit():
                        #print("GOT ACK... %s" % tcp_packet.get_acknowledgment_number())
                        if self.tcb.snd_una < tcp_packet.get_acknowledgment_number() and tcp_packet.get_acknowledgment_number() <= self.tcb.snd_nxt:
                            acked_bytes = tcp_packet.get_acknowledgment_number() - self.tcb.snd_una - 1
                            
                            self.tcb.snd_una = tcp_packet.get_acknowledgment_number()
                            #print("SETTING UNA ---------------- %s" % self.tcb.snd_una)
                            # Remove the packets that have sequnce <= self.tcb.snd_una
                            stimestamp, rto, packet = self.send_queue[tcp_packet.get_acknowledgment_number()]
                            rtimestamp = time()
                            rtt = rtimestamp - stimestamp
                            self.srtt = (ALPHA * rtt) + ((1 - ALPHA) * rtt)
                            self.rto = min(UBOUND, max(LBOUND,(BETA * self.srtt)))
                            
                            old_tcp_packet = TCPPacket(packet.get_payload())
                            #self.bytes_in_flight -= acked_bytes

                            seqs = list(self.send_queue.keys())
                            for seq in seqs:
                                if seq <= self.tcb.snd_una:
                                    del self.send_queue[seq]
                            
                            #print("REMOVING PACKETS FROM THE SEND QUEUE")

                            if self.tcb.cwnd < self.ssthresh:
                                self.tcb.cwnd += MSS
                            else:
                                self.tcb.cwnd += MSS * MSS / self.tcb.cwnd
                                
                            if self.tcb.snd_wl1 < tcp_packet.get_sequence_number() or \
                                (self.tcb.snd_wl1 == tcp_packet.get_sequence_number() and \
                                self.tcb.snd_wl2 <= tcp_packet.get_acknowledgment_number()):
                                self.tcb.snd_wnd = tcp_packet.get_window()
                                self.tcb.snd_wl1 = tcp_packet.get_sequence_number()
                                self.tcb.snd_wl2 = tcp_packet.get_acknowledgment_number()
                        if tcp_packet.get_acknowledgment_number() > self.tcb.snd_nxt:
                            # Send ACK and drop the packet
                            #print("ACK is not acknowledging anything... sending ACK in response")
                            continue
                        if self.tcb.snd_una > tcp_packet.get_acknowledgment_number():
                            # Duplicate
                            #print("DUPLICATE.....")
                            continue

                    if tcp_packet.get_ack_bit():
                        self.state = self.states.TIME_WAIT
                        """
                        Start the time-wait timer, turn off the other timers.
                        """
                elif self.state == self.states.FIN_WAIT_1:
                    # First check
                    #print("GOT PACKET FROM THE OTHER SIDE")
                    not_acceptable = False
                    if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                        #print("Window is zero and the package is > 0")
                        not_acceptable = True

                    if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                        if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                            #print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                        if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                            #print("Window > 0 plen=0 but the sequance is out of window")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                        if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                                (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                                self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                            #print("W>0 plen>0 but the rcv_nxt <= seq < ")
                            not_acceptable = True
                        
                    if not_acceptable:
                        #print("Not acceptable data received")
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        continue
                    
                    # Second check
                    if tcp_packet.get_rst_bit():
                        # Clean all queues
                        self.state = self.states.CLOSED
                        self.tcb = None

                    # Third check
                    if tcp_packet.get_syn_bit():
                        # Send reset packet
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_rst_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        # Clean all queues
                        self.state = self.states.CLOSED
                        self.receive_queue = {}
                        self.send_queue = {}
                        ##print("Moving to close state CLOSE WAIT 2")
                        self.tcb = None
                        continue

                    # Fifth check
                    if not tcp_packet.get_ack_bit():
                        # Drop the packet and return
                        continue
                    

                    if tcp_packet.get_ack_bit():
                        #print("GOT ACK... %s" % tcp_packet.get_acknowledgment_number())
                        if self.tcb.snd_una < tcp_packet.get_acknowledgment_number() and tcp_packet.get_acknowledgment_number() <= self.tcb.snd_nxt:
                            self.tcb.snd_una = tcp_packet.get_acknowledgment_number()
                            #print("SETTING UNA ---------------- %s" % self.tcb.snd_una)
                            # Remove the packets that have sequnce <= self.tcb.snd_una
                            stimestamp, rto, packet = self.send_queue[tcp_packet.get_acknowledgment_number()]
                            rtimestamp = time()
                            rtt = rtimestamp - stimestamp
                            self.srtt = (ALPHA * rtt) + ((1 - ALPHA) * rtt)
                            self.rto = min(UBOUND, max(LBOUND,(BETA * self.srtt)))
                            
                            old_tcp_packet = TCPPacket(packet.get_payload())
                            #self.bytes_in_flight -= len(old_tcp_packet.get_data())

                            seqs = list(self.send_queue.keys())
                            for seq in seqs:
                                if seq <= self.tcb.snd_una:
                                    del self.send_queue[seq]
                            
                            #print("REMOVING PACKETS FROM THE SEND QUEUE")

                            if self.tcb.cwnd < self.ssthresh:
                                self.tcb.cwnd += MSS
                            else:
                                self.tcb.cwnd += MSS * MSS / self.tcb.cwnd
                                
                            if self.tcb.snd_wl1 < tcp_packet.get_sequence_number() or \
                                (self.tcb.snd_wl1 == tcp_packet.get_sequence_number() and \
                                self.tcb.snd_wl2 <= tcp_packet.get_acknowledgment_number()):
                                self.tcb.snd_wnd = tcp_packet.get_window()
                                self.tcb.snd_wl1 = tcp_packet.get_sequence_number()
                                self.tcb.snd_wl2 = tcp_packet.get_acknowledgment_number()
                        if tcp_packet.get_acknowledgment_number() > self.tcb.snd_nxt:
                            # Send ACK and drop the packet
                            #print("ACK is not acknowledging anything... sending ACK in response")
                            continue
                        if self.tcb.snd_una > tcp_packet.get_acknowledgment_number():
                            # Duplicate
                            #print("DUPLICATE.....")
                            continue
                    # Check if ACK for FIN 

                    
                    if tcp_packet.get_urg_bit():
                        self.tcb.rcv_up = max(self.tcb.rcv_up, tcp_packet.get_urgent_pointer())
                        # Signal the user
                    
                    elif tcp_packet.get_fin_bit():
                        # send ACK packet
                        self.state = self.states.CLOSE_WAIT

                    #print("GOT DATA IN THE TCP PACKET:")
                    #print(len(tcp_packet.get_data()) > 0)
                    #print(tcp_packet.get_data())

                    # Seventh check
                    if len(tcp_packet.get_data()) > 0:
                        #print("Adding the packet into the receive queue")
                        self.receive_queue[tcp_packet.get_sequence_number()] = (time(), ipv4packet)
                    else:
                        continue

                    # Advance the RCV_NXT
                    seqs = list(self.receive_queue.keys())
                    seqs.sort()
                    for seq in seqs:
                        if self.tcb.rcv_nxt == seq:
                            timestamp, packet = self.receive_queue[seq]
                            tcp_packet = TCPPacket(packet.get_payload())
                            self.tcb.rcv_nxt += len(tcp_packet.get_data())
                    # Process the data in TCP packet
                    tcp_packet = packets.TCPPacket()
                    tcp_packet.set_source_port(self.sport)
                    tcp_packet.set_destination_port(self.dport)
                    tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                    tcp_packet.set_sequence_number(self.tcb.snd_nxt)                
                    tcp_packet.set_window(self.tcb.snd_wnd)
                    tcp_packet.set_ack_bit(1)
                    tcp_packet.set_data_offset(5)
                    ipv4packet = packets.IPv4Packet()
                    ipv4packet.set_source_address(self.src_bytes)
                    ipv4packet.set_destination_address(self.dst_bytes)
                    ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                    ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                    tcp_packet.set_checksum(0)
                    pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                            self.dst_bytes, \
                                                            Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                    tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                    tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                    ipv4packet.set_payload(tcp_packet.get_buffer())
                    self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))

                    if tcp_packet.get_fin_bit():
                        self.state = self.states.TIME_WAIT
                        # Send ACK packet
                    
                    # Eight check
                    if tcp_packet.get_ack_bit():
                        self.state = self.states.FIN_WAIT_2
                    elif tcp_packet.get_fin_bit():
                        """
                        If our FIN has been ACKed (perhaps in this segment), then
                        enter TIME-WAIT, start the time-wait timer, turn off the other
                        timers; otherwise enter the CLOSING state.
                        """ 
                        self.state = self.states.CLOSING
                        # Send ACK
                elif self.state == self.states.FIN_WAIT_2:
                    # First check
                    #print("GOT PACKET FROM THE OTHER SIDE")
                    not_acceptable = False
                    if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                        #print("Window is zero and the package is > 0")
                        not_acceptable = True

                    if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                        if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                            #print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                        if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                            #print("Window > 0 plen=0 but the sequance is out of window")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                        if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                                (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                                self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                            #print("W>0 plen>0 but the rcv_nxt <= seq < ")
                            not_acceptable = True
                        
                    if not_acceptable:
                        #print("Not acceptable data received")
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        continue
                    
                    # Second check
                    if tcp_packet.get_rst_bit():
                        # Clean all queues
                        self.state = self.states.CLOSED
                        self.tcb = None
                        #print("Moving to close state FIN WAIT 2 1")

                    # Third check
                    if tcp_packet.get_syn_bit():
                        # Send reset packet
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_rst_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        # Clean all queues
                        self.state = self.states.CLOSED
                        self.receive_queue = {}
                        self.send_queue = {}
                        ##print("Moving to close state CLOSE WAIT 2")
                        self.tcb = None
                        continue

                    # Fifth check
                    if not tcp_packet.get_ack_bit():
                        # Drop the packet and return
                        continue
                    

                    if tcp_packet.get_ack_bit():
                        #print("GOT ACK... %s" % tcp_packet.get_acknowledgment_number())
                        if self.tcb.snd_una < tcp_packet.get_acknowledgment_number() and tcp_packet.get_acknowledgment_number() <= self.tcb.snd_nxt:
                            self.tcb.snd_una = tcp_packet.get_acknowledgment_number()
                            #print("SETTING UNA ---------------- %s" % self.tcb.snd_una)
                            # Remove the packets that have sequnce <= self.tcb.snd_una
                            stimestamp, rto, packet = self.send_queue[tcp_packet.get_acknowledgment_number()]
                            rtimestamp = time()
                            rtt = rtimestamp - stimestamp
                            self.srtt = (ALPHA * rtt) + ((1 - ALPHA) * rtt)
                            self.rto = min(UBOUND, max(LBOUND,(BETA * self.srtt)))
                            
                            old_tcp_packet = TCPPacket(packet.get_payload())
                            #self.bytes_in_flight -= len(old_tcp_packet.get_data())

                            seqs = list(self.send_queue.keys())
                            for seq in seqs:
                                if seq <= self.tcb.snd_una:
                                    del self.send_queue[seq]
                            
                            #print("REMOVING PACKETS FROM THE SEND QUEUE")

                            if self.tcb.cwnd < self.ssthresh:
                                self.tcb.cwnd += MSS
                            else:
                                self.tcb.cwnd += MSS * MSS / self.tcb.cwnd
                                
                            if self.tcb.snd_wl1 < tcp_packet.get_sequence_number() or \
                                (self.tcb.snd_wl1 == tcp_packet.get_sequence_number() and \
                                self.tcb.snd_wl2 <= tcp_packet.get_acknowledgment_number()):
                                self.tcb.snd_wnd = tcp_packet.get_window()
                                self.tcb.snd_wl1 = tcp_packet.get_sequence_number()
                                self.tcb.snd_wl2 = tcp_packet.get_acknowledgment_number()
                        if tcp_packet.get_acknowledgment_number() > self.tcb.snd_nxt:
                            # Send ACK and drop the packet
                            #print("ACK is not acknowledging anything... sending ACK in response")
                            continue
                        if self.tcb.snd_una > tcp_packet.get_acknowledgment_number():
                            # Duplicate
                            #print("DUPLICATE.....")
                            continue
                    
                    if tcp_packet.get_urg_bit():
                        self.tcb.rcv_up = max(self.tcb.rcv_up, tcp_packet.get_urgent_pointer())
                        # Signal the user
                    
                    elif tcp_packet.get_fin_bit():
                        # send ACK packet
                        self.state = self.states.CLOSE_WAIT

                    #print("GOT DATA IN THE TCP PACKET:")
                    #print(len(tcp_packet.get_data()) > 0)
                    #print(tcp_packet.get_data())

                    # Seventh check
                    if len(tcp_packet.get_data()) > 0:
                        #print("Adding the packet into the receive queue")
                        self.receive_queue[tcp_packet.get_sequence_number()] = (time(), ipv4packet)
                    else:
                        continue

                    # Advance the RCV_NXT
                    seqs = list(self.receive_queue.keys())
                    seqs.sort()
                    for seq in seqs:
                        if self.tcb.rcv_nxt == seq:
                            timestamp, packet = self.receive_queue[seq]
                            tcp_packet = TCPPacket(packet.get_payload())
                            self.tcb.rcv_nxt += len(tcp_packet.get_data())
                    # Process the data in TCP packet
                    tcp_packet = packets.TCPPacket()
                    tcp_packet.set_source_port(self.sport)
                    tcp_packet.set_destination_port(self.dport)
                    tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                    tcp_packet.set_sequence_number(self.tcb.snd_nxt)                
                    tcp_packet.set_window(self.tcb.snd_wnd)
                    tcp_packet.set_ack_bit(1)
                    tcp_packet.set_data_offset(5)
                    ipv4packet = packets.IPv4Packet()
                    ipv4packet.set_source_address(self.src_bytes)
                    ipv4packet.set_destination_address(self.dst_bytes)
                    ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                    ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                    tcp_packet.set_checksum(0)
                    pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                            self.dst_bytes, \
                                                            Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                    tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                    tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                    ipv4packet.set_payload(tcp_packet.get_buffer())
                    self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))

                    if tcp_packet.get_fin_bit():
                        self.state = self.states.TIME_WAIT
                        # Send ACK packet
                    pass
                elif self.state == self.states.SYN_SENT:
                    sequence = tcp_packet.get_sequence_number() + 1
                    window = tcp_packet.get_window()

                    self.tcb.rcv_nxt = sequence

                    if tcp_packet.get_ack_bit():
                        #print(tcp_packet.get_acknowledgment_number())
                        if tcp_packet.get_acknowledgment_number() <= self.tcb.iss or tcp_packet.get_acknowledgment_number() > self.tcb.snd_nxt:
                            # Drop the packet and send RST
                            continue
                        if not (tcp_packet.get_acknowledgment_number() >= self.tcb.snd_una and tcp_packet.get_acknowledgment_number() <= self.tcb.snd_nxt):
                            # ACK is not acceptable Drop the packet
                            continue
                        if tcp_packet.get_rst_bit():
                            self.state = self.states.CLOSED
                    else:
                        if tcp_packet.get_rst_bit():
                            # Drop the packet and return
                            continue
                    
                    if tcp_packet.get_syn_bit():

                        self.tcb.rcv_nxt = tcp_packet.get_sequence_number() + 1                    
                        self.tcb.irs = tcp_packet.get_sequence_number()
                        self.last_recv_sequence = self.tcb.irs
                        self.tcb.snd_una = tcp_packet.get_acknowledgment_number()
                        self.tcb.snd_wnd = config.get("IW", 4096)
                        self.tcb.rcv_wnd = config.get("IW", 4096)

                        # Remove packets in retransmission queue

                        if self.tcb.snd_una > self.tcb.iss:
                            self.state = self.states.ESTABLISHED
                            print("Connections established...... %s %s %s %s" % (self.src, self.dst, self.sport, self.dport))

                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_data_offset(5)

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        #print("Sending the ack packet in response to SYN+ACK")
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))

                        self.tcb.rwnd = window
                    if not tcp_packet.get_ack_bit() and tcp_packet.get_syn_bit():
                        self.state = self.states.SYN_RECEIVED

                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.iss)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_syn_bit(1)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                elif self.state == self.states.ESTABLISHED:
                    # First check
                    #print("GOT PACKET FROM THE OTHER SIDE")
                    not_acceptable = False
                    if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                        #print("Window is zero and the package is > 0")
                        not_acceptable = True

                    if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                        if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                            #print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                        if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                            #print("Window > 0 plen=0 but the sequance is out of window")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                        if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                                (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                                self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                            #print("W>0 plen>0 but the rcv_nxt <= seq < ")
                            not_acceptable = True
                        
                    if not_acceptable:
                        #print("Not acceptable data received")
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        continue
                    
                    # Second check
                    if tcp_packet.get_rst_bit():
                        # Clean all queues
                        self.state = self.states.CLOSED
                        self.tcb = None
                        
                    # Third check
                    if tcp_packet.get_syn_bit():
                        # Send reset packet
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_rst_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        # Clean all queues
                        self.state = self.states.CLOSED
                        self.receive_queue = {}
                        self.send_queue = {}
                        ##print("Moving to close state CLOSE WAIT 2")
                        self.tcb = None
                        continue
                    
                    # Fifth check
                    if not tcp_packet.get_ack_bit():
                        # Drop the packet and return
                        continue

                    if tcp_packet.get_ack_bit():
                        #print("GOT ACK... %s" % tcp_packet.get_acknowledgment_number())
                        if self.tcb.snd_una < tcp_packet.get_acknowledgment_number() and tcp_packet.get_acknowledgment_number() <= self.tcb.snd_nxt:
                            acked_bytes = tcp_packet.get_acknowledgment_number() - self.tcb.snd_una - 1
                            self.tcb.snd_una = tcp_packet.get_acknowledgment_number()
                            #print("SETTING UNA ---------------- %s" % self.tcb.snd_una)
                            # Remove the packets that have sequnce <= self.tcb.snd_una
                            stimestamp, rto, packet = self.send_queue[tcp_packet.get_acknowledgment_number()]
                            rtimestamp = time()
                            rtt = rtimestamp - stimestamp
                            self.srtt = (ALPHA * rtt) + ((1 - ALPHA) * rtt)
                            self.rto = min(UBOUND, max(LBOUND,(BETA * self.srtt)))
                            
                            old_tcp_packet = TCPPacket(packet.get_payload())
                            #self.bytes_in_flight -= len(old_tcp_packet.get_data())
                            #self.bytes_in_flight -= acked_bytes

                            seqs = list(self.send_queue.keys())
                            for seq in seqs:
                                if seq <= self.tcb.snd_una:
                                    self.bytes_in_flight -= len(old_tcp_packet.get_data())
                                    del self.send_queue[seq]
                            
                            #print("REMOVING PACKETS FROM THE SEND QUEUE")

                            if self.tcb.cwnd < self.ssthresh:
                                self.tcb.cwnd += MSS
                            else:
                                self.tcb.cwnd += MSS * MSS / self.tcb.cwnd
                                
                            if self.tcb.snd_wl1 < tcp_packet.get_sequence_number() or \
                                (self.tcb.snd_wl1 == tcp_packet.get_sequence_number() and \
                                self.tcb.snd_wl2 <= tcp_packet.get_acknowledgment_number()):
                                self.tcb.snd_wnd = tcp_packet.get_window()
                                self.tcb.snd_wl1 = tcp_packet.get_sequence_number()
                                self.tcb.snd_wl2 = tcp_packet.get_acknowledgment_number()
                        if tcp_packet.get_acknowledgment_number() > self.tcb.snd_nxt:
                            # Send ACK and drop the packet
                            #print("ACK is not acknowledging anything... sending ACK in response")
                            continue
                        if self.tcb.snd_una > tcp_packet.get_acknowledgment_number():
                            # Duplicate
                            #print("DUPLICATE.....")
                            continue
                    
                    if tcp_packet.get_urg_bit():
                        self.tcb.rcv_up = max(self.tcb.rcv_up, tcp_packet.get_urgent_pointer())
                        # Signal the user
                    
                    elif tcp_packet.get_fin_bit():
                        # send ACK packet
                        self.state = self.states.CLOSE_WAIT

                    #print("GOT DATA IN THE TCP PACKET:")
                    #print(len(tcp_packet.get_data()) > 0)
                    #print(tcp_packet.get_data())

                    # Seventh check
                    if len(tcp_packet.get_data()) > 0:
                        #print("Adding the packet into the receive queue")
                        self.receive_queue[tcp_packet.get_sequence_number()] = (time(), ipv4packet)
                    else:
                        continue

                    # Advance the RCV_NXT
                    seqs = list(self.receive_queue.keys())
                    seqs.sort()
                    for seq in seqs:
                        if self.tcb.rcv_nxt == seq:
                            timestamp, packet = self.receive_queue[seq]
                            tcp_packet = TCPPacket(packet.get_payload())
                            self.tcb.rcv_nxt += len(tcp_packet.get_data())
                    # Process the data in TCP packet
                    tcp_packet = packets.TCPPacket()
                    tcp_packet.set_source_port(self.sport)
                    tcp_packet.set_destination_port(self.dport)
                    tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                    tcp_packet.set_sequence_number(self.tcb.snd_nxt)                
                    tcp_packet.set_window(self.tcb.snd_wnd)
                    tcp_packet.set_ack_bit(1)
                    tcp_packet.set_data_offset(5)
                    ipv4packet = packets.IPv4Packet()
                    ipv4packet.set_source_address(self.src_bytes)
                    ipv4packet.set_destination_address(self.dst_bytes)
                    ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                    ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                    tcp_packet.set_checksum(0)
                    pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                            self.dst_bytes, \
                                                            Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                    tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                    tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                    ipv4packet.set_payload(tcp_packet.get_buffer())
                    self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))

                    # Eigth check
                    if tcp_packet.get_fin_bit():
                        self.state = self.states.CLOSE_WAIT
                    
                    continue;
                elif self.state == self.states.LISTEN:
                    self.dport = tcp_packet.get_source_port()
                    self.sport = tcp_packet.get_destination_port()
                    self.dst_bytes = ipv4packet.get_source_address()
                    self.dst = Misc.bytes_to_ipv4_string(ipv4packet.get_source_address())
                    self.src_bytes = ipv4packet.get_destination_address()
                    self.src = Misc.bytes_to_ipv4_string(ipv4packet.get_destination_address())
                    sequence = tcp_packet.get_sequence_number()
                    if tcp_packet.get_rst_bit():
                        continue
                    if tcp_packet.get_ack_bit():
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_sequence_number(sequence)
                        tcp_packet.set_rst_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                    if tcp_packet.get_syn_bit():
                        # Send SYN+ACK
                        self.tcb = TransmissionControlBlock()
                        self.tcb.rcv_nxt = sequence + 1
                        self.tcb.irs = sequence
                        self.last_recv_sequence = self.tcb.irs
                        self.tcb.iss = TCPUtils.generate_isn()
                        self.tcb.snd_nxt = self.tcb.iss + 1
                        self.tcb.snd_una = self.tcb.iss

                        self.tcb.snd_wnd = config.get("IW", 4096)
                        self.tcb.rcv_wnd = config.get("IW", 4096)
                        
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.iss)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_syn_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))

                        self.state = self.states.SYN_RECEIVED
                elif self.state == self.states.SYN_RECEIVED:
                    # Second check
                    not_acceptable = False
                    if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                        #print("Window is zero and the package is > 0")
                        not_acceptable = True

                    if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                        if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                            #print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                        if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                            #print("Window > 0 plen=0 but the sequance is out of window")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                        if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                                (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                                self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                            #print("W>0 plen>0 but the rcv_nxt <= seq < ")
                            not_acceptable = True
                    if not_acceptable:
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        continue
                    
                    # Second check
                    if tcp_packet.get_rst_bit():
                        if self.passive:
                            self.state = self.states.LISTEN
                            continue
                        else:
                            self.state = self.states.CLOSED
                            self.tcb = None
                        continue
                    
                    # Third check
                    if tcp_packet.get_syn_bit():
                        # Send reset packet
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_rst_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        print(list(ipv4packet.get_buffer()))
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        # Clean all queues
                        self.state = self.states.CLOSED
                        self.receive_queue = {}
                        self.send_queue = {}
                        ##print("Moving to close state CLOSE WAIT 2")
                        self.tcb = None
                        continue
                    
                    # Fifth check
                    if tcp_packet.get_ack_bit():
                        if self.tcb.snd_una < tcp_packet.get_acknowledgment_number() and tcp_packet.get_acknowledgment_number()<= self.tcb.snd_nxt:
                            self.state = self.states.ESTABLISHED
                            self.tcb.snd_wnd = tcp_packet.get_window()
                        else:
                            # Send reset packet
                            tcp_packet = packets.TCPPacket()
                            tcp_packet.set_source_port(self.sport)
                            tcp_packet.set_destination_port(self.dport)
                            
                            # Copy original sequence into the acknowledgement sequence
                            tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                            tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                            tcp_packet.set_window(self.tcb.rcv_wnd)
                            tcp_packet.set_ack_bit(1)
                            tcp_packet.set_rst_bit(1)
                            tcp_packet.set_data_offset(5)    

                            ipv4packet = packets.IPv4Packet()
                            ipv4packet.set_source_address(self.src_bytes)
                            ipv4packet.set_destination_address(self.dst_bytes)
                            ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                            ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                            tcp_packet.set_checksum(0)

                            pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                    self.dst_bytes, \
                                                                    Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                            
                            tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                            tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                            ipv4packet.set_payload(tcp_packet.get_buffer())
                            self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                    # Eigth check
                    if tcp_packet.get_fin_bit():
                        self.state = self.states.CLOSE_WAIT
                elif self.state == self.states.LAST_ACK:
                    # First check
                    not_acceptable = False
                    if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                        #print("Window is zero and the package is > 0")
                        not_acceptable = True

                    if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                        if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                            #print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                        if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                            #print("Window > 0 plen=0 but the sequance is out of window")
                            not_acceptable = True

                    if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                        if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                                (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                                self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                            #print("W>0 plen>0 but the rcv_nxt <= seq < ")
                            not_acceptable = True
                    if not not_acceptable:
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        continue
                    
                    # Second check
                    if tcp_packet.get_ack_bit():
                        self.state = self.states.CLOSED
                        self.tcb = None

                    # Third check
                    if tcp_packet.get_syn_bit():
                        # Send reset packet
                        tcp_packet = packets.TCPPacket()
                        tcp_packet.set_source_port(self.sport)
                        tcp_packet.set_destination_port(self.dport)
                        
                        # Copy original sequence into the acknowledgement sequence
                        tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                        tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                        tcp_packet.set_window(self.tcb.rcv_wnd)
                        tcp_packet.set_ack_bit(1)
                        tcp_packet.set_rst_bit(1)
                        tcp_packet.set_data_offset(5)    

                        ipv4packet = packets.IPv4Packet()
                        ipv4packet.set_source_address(self.src_bytes)
                        ipv4packet.set_destination_address(self.dst_bytes)
                        ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                        ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                        tcp_packet.set_checksum(0)

                        pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                                self.dst_bytes, \
                                                                Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                        tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                        tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                        ipv4packet.set_payload(tcp_packet.get_buffer())
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        # Clean all queues
                        self.state = self.states.CLOSED
                        self.receive_queue = {}
                        self.send_queue = {}
                        ##print("Moving to close state CLOSE WAIT 2")
                        self.tcb = None
                        continue

                    # Fourth check
                    # Check if the packets ACKs FIN packet

                    tcp_packet = packets.TCPPacket()
                    tcp_packet.set_source_port(self.sport)
                    tcp_packet.set_destination_port(self.dport)
                        
                    # Copy original sequence into the acknowledgement sequence
                    tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                    tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                    tcp_packet.set_window(self.tcb.rcv_wnd)
                    tcp_packet.set_ack_bit(1)
                    tcp_packet.set_data_offset(5)    

                    ipv4packet = packets.IPv4Packet()
                    ipv4packet.set_source_address(self.src_bytes)
                    ipv4packet.set_destination_address(self.dst_bytes)
                    ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                    ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                    tcp_packet.set_checksum(0)

                    pseudo_header = Misc.make_pseudo_header(self.src_bytes, \
                                                            self.dst_bytes, \
                                                            Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                        
                    tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                    tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                    ipv4packet.set_payload(tcp_packet.get_buffer())
                    self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
            except Exception as e:
                traceback.print_exc()
                print("Got exception in read loop %s" % str(e))
                #print(traceback.format_exc())
            
    def __send__(self):
        while True:
            if self.state == self.states.CLOSED:
                print("Opening connection...")
                self.tcb = TransmissionControlBlock()
                self.tcb.iss = TCPUtils.generate_isn()
                self.tcb.snd_una = self.tcb.iss
                self.tcb.snd_nxt = self.tcb.iss + 1
                #print("Setting TCB ISS")
                self.state = self.states.SYN_SENT
                
                tcp_packet = packets.TCPPacket()
                tcp_packet.set_source_port(self.sport)
                tcp_packet.set_destination_port(self.dport)
                tcp_packet.set_syn_bit(1)
                tcp_packet.set_sequence_number(self.tcb.snd_una)
                tcp_packet.set_data_offset(5)

                mss_option = packets.TCPMSSOption()
                mss_option.set_mss(MSS)
                mss_option.set_kind(packets.TCP_MSS_OPTION_KIND)
                
                end_option = packets.TCPOption()
                end_option.set_kind(packets.TCP_OPTION_END_OF_OPTION_KIND)

                noop_option = packets.TCPOption()
                noop_option.set_kind(packets.TCP_NOOP_OPTION_KIND)

                ipv4packet = packets.IPv4Packet()
                ipv4packet.set_source_address(self.src_bytes)
                ipv4packet.set_destination_address(self.dst_bytes)
                ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                tcp_packet.set_checksum(0)

                tcp_packet.set_options([mss_option, noop_option, end_option])

                pseudo_header = Misc.make_pseudo_header(self.src_bytes, self.dst_bytes, Misc.int_to_bytes(len(tcp_packet.get_buffer())))
                
                tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())

                tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                ipv4packet.set_payload(tcp_packet.get_buffer())

                self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                continue
            elif self.state == self.states.ESTABLISHED:
                plen = MSS
                if len(self.data_to_send) < MSS:
                    plen = len(self.data_to_send)
                if plen == 0:
                    continue

                #if self.tcb.snd_wnd

                max_window = min(self.tcb.cwnd, self.tcb.snd_wnd)

                if self.bytes_in_flight + plen > max_window:
                    continue

                data = self.data_to_send[:plen]
                self.data_to_send = self.data_to_send[plen:]

                tcp_packet = packets.TCPPacket()
                tcp_packet.set_source_port(self.sport)
                tcp_packet.set_destination_port(self.dport)

                # Copy original sequence into the acknowledgement sequence
                tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
                tcp_packet.set_sequence_number(self.tcb.snd_nxt)
                tcp_packet.set_ack_bit(1)
                tcp_packet.set_window(self.tcb.rcv_wnd)
                tcp_packet.set_data_offset(5)

                ipv4packet = packets.IPv4Packet()
                ipv4packet.set_source_address(self.src_bytes)
                ipv4packet.set_destination_address(self.dst_bytes)
                ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
                ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
                tcp_packet.set_checksum(0)
                tcp_packet.set_data(data)

                pseudo_header = Misc.make_pseudo_header(self.src_bytes, self.dst_bytes, Misc.int_to_bytes(len(tcp_packet.get_buffer())))                        
                tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                
                tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
                ipv4packet.set_payload(tcp_packet.get_buffer())

                self.tcb.snd_nxt += plen

                # Put into the send queue timestamp, RTO, ipv4packet
                #print("ADDDED SEQ TO SEND QUEUE %s" % self.tcb.snd_nxt)
                self.send_queue[self.tcb.snd_nxt] = (time(), time() + self.rto, ipv4packet)
                self.bytes_in_flight += len(tcp_packet.get_data())
                
                self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                #self.__noop__()
            elif self.state == self.states.LISTEN:
                # Send SYN packet
                pass

    def open(self, src, dst, src_port, dst_port, listen = False):
                
        if not listen:
            self.src = src
            self.dst = dst
            self.src_bytes = Misc.ipv4_address_to_bytes(src)
            self.dst_bytes = Misc.ipv4_address_to_bytes(dst)
            self.sport = src_port
            self.dport = dst_port
        else:
            self.src = src
            self.src_bytes = Misc.ipv4_address_to_bytes(src)
            self.sport = src_port

        self.states = TCPStates()
        if listen:
            self.state = self.states.LISTEN
        else:
            self.state = self.states.CLOSED
        #    #print("Moving to close state open call")
        
        # creates a raw socket and binds it to the source address
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, packets.TCP_PROTOCOL_NUMBER)
        self.socket.bind((src, 0))
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1);


        self.recv_thread = threading.Thread(target = self.__recv__, args = (), daemon = True);
        self.send_thread = threading.Thread(target = self.__send__, args = (), daemon = True);
        self.maintenance_thread = threading.Thread(target = self.__maintenance__, args = (), daemon = True);

        self.recv_thread.start()
        self.send_thread.start()
        self.maintenance_thread.start()
    
    def listen(self):
        while True:
            if self.state == self.states.ESTABLISHED:
                print("Connection was accepted src=%s dst=%s sport=%s dport=%s" % (self.src, self.dst, self.sport, self.dport))
                print("You can start utilizing the transport...")
                break
            self.__noop__()
        
    def send(self, data):
        self.data_to_send += bytearray(data)

    def receive(self, length):
        if len(self.received_data) >= length:
            buf = self.received_data[:length]
            self.received_data = self.received_data[length:]
            return buf
        elif len(self.received_data) > 0:
            buf = self.received_data[:]
            self.received_data = []
            return buf

    def close(self):
        # Send FIN packet
        if self.state == self.states.CLOSE_WAIT:
            self.state = self.states.CLOSING
            tcp_packet = packets.TCPPacket()
            
            tcp_packet.set_source_port(self.sport)
            tcp_packet.set_destination_port(self.dport)

            # Copy original sequence into the acknowledgement sequence
            tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
            tcp_packet.set_sequence_number(self.tcb.snd_nxt)
            tcp_packet.set_fin_bit(1)
            tcp_packet.set_window(0)
            tcp_packet.set_data_offset(5)

            ipv4packet = packets.IPv4Packet()
            ipv4packet.set_source_address(self.src_bytes)
            ipv4packet.set_destination_address(self.dst_bytes)
            ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
            ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
            tcp_packet.set_checksum(0)

            pseudo_header = Misc.make_pseudo_header(self.src_bytes, self.dst_bytes, Misc.int_to_bytes(len(tcp_packet.get_buffer())))                        
            tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                
            tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
            ipv4packet.set_payload(tcp_packet.get_buffer())

            self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
            # send FIN packet
            pass
        elif self.state == self.states.SYN_SENT:
            self.state = self.states.CLOSED
            self.tcb = None
        elif self.state == self.states.SYN_RECEIVED:
            self.state = self.states.FIN_WAIT_1
            
            tcp_packet = packets.TCPPacket()
            
            tcp_packet.set_source_port(self.sport)
            tcp_packet.set_destination_port(self.dport)

            # Copy original sequence into the acknowledgement sequence
            tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
            tcp_packet.set_sequence_number(self.tcb.snd_nxt)
            tcp_packet.set_fin_bit(1)
            tcp_packet.set_window(0)
            tcp_packet.set_data_offset(5)

            ipv4packet = packets.IPv4Packet()
            ipv4packet.set_source_address(self.src_bytes)
            ipv4packet.set_destination_address(self.dst_bytes)
            ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
            ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
            tcp_packet.set_checksum(0)

            pseudo_header = Misc.make_pseudo_header(self.src_bytes, self.dst_bytes, Misc.int_to_bytes(len(tcp_packet.get_buffer())))                        
            tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                
            tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
            ipv4packet.set_payload(tcp_packet.get_buffer())

            self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
            # Send FIN packet
        elif self.state == self.states.LISTEN:
            self.state = self.states.CLOSED
            self.tcb = None
        elif self.state == self.states.ESTABLISHED:
            # send FIN packet
            self.state = self.states.FIN_WAIT_1

            tcp_packet = packets.TCPPacket()
            
            tcp_packet.set_source_port(self.sport)
            tcp_packet.set_destination_port(self.dport)

            # Copy original sequence into the acknowledgement sequence
            tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
            tcp_packet.set_sequence_number(self.tcb.snd_nxt)
            tcp_packet.set_fin_bit(1)
            tcp_packet.set_window(0)
            tcp_packet.set_data_offset(5)

            ipv4packet = packets.IPv4Packet()
            ipv4packet.set_source_address(self.src_bytes)
            ipv4packet.set_destination_address(self.dst_bytes)
            ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
            ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
            tcp_packet.set_checksum(0)

            pseudo_header = Misc.make_pseudo_header(self.src_bytes, self.dst_bytes, Misc.int_to_bytes(len(tcp_packet.get_buffer())))                        
            tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                
            tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
            ipv4packet.set_payload(tcp_packet.get_buffer())

            self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
        elif self.state == self.states.CLOSING or \
            self.state == self.states.LAST_ACK or \
            self.state == self.states.TIME_WAIT:
            self.state = self.states.CLOSED
            self.tcb = None
    def abort(self):
        if self.state == self.states.SYN_SENT:
            self.state = self.states.CLOSED
            self.tcb = None
        elif self.state == self.states.LISTEN:
            self.state = self.states.CLOSED
            self.tcb = None
        elif self.state == self.states.ESTABLISHED or \
            self.state == self.states.SYN_RECEIVED or \
                self.state == self.states.FIN_WAIT_1 or \
                    self.state == self.states.FIN_WAIT_2:
            # send FIN packet
            self.state = self.states.FIN_WAIT_1

            tcp_packet = packets.TCPPacket()
            
            tcp_packet.set_source_port(self.sport)
            tcp_packet.set_destination_port(self.dport)

            # Copy original sequence into the acknowledgement sequence
            tcp_packet.set_acknowledgment_number(self.tcb.rcv_nxt)
            tcp_packet.set_sequence_number(self.tcb.snd_nxt)
            tcp_packet.set_rst_bit(1)
            tcp_packet.set_window(0)
            tcp_packet.set_data_offset(5)

            ipv4packet = packets.IPv4Packet()
            ipv4packet.set_source_address(self.src_bytes)
            ipv4packet.set_destination_address(self.dst_bytes)
            ipv4packet.set_protocol(packets.TCP_PROTOCOL_NUMBER)
            ipv4packet.set_ttl(packets.IP_DEFAULT_TTL)
            tcp_packet.set_checksum(0)

            pseudo_header = Misc.make_pseudo_header(self.src_bytes, self.dst_bytes, Misc.int_to_bytes(len(tcp_packet.get_buffer())))                        
            tcp_checksum = Checksum.checksum(pseudo_header + tcp_packet.get_buffer())
                
            tcp_packet.set_checksum(tcp_checksum & 0xFFFF)
            ipv4packet.set_payload(tcp_packet.get_buffer())

            self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))

            self.state = self.states.CLOSED
            self.tcb = None
    def status(self):
        response = ""
        
        response += "Size of the send queue: " + str(len(self.send_queue)) + "\n"
        response += "Size of the receive queue: " + str(len(self.receive_queue)) + "\n"
        response += "Last received sequence: " + str(self.last_recv_sequence) + "\n"
        response += "Bytes in flight: " + str(self.bytes_in_flight) + "\n"
        response += "RTT:" + str(self.srtt) + "\n"
        response += "RTO:" + str(self.rto) + "\n"
        if self.tcb:
            response += "Receiver window:" + str(self.tcb.rcv_wnd) + "\n"
            response += "Sender window:" + str(self.tcb.snd_wnd) + "\n"
            response += "Next sequence to expect in sequence field from the sender:" + str(self.tcb.rcv_nxt) + "\n"
            response += "Next sequence to expect in acknoledgement field from the sender:" + str(self.tcb.snd_nxt) + "\n"
        response += "State: " + str(self.state) + "\n"
        return response
    
