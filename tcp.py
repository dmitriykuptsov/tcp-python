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

MTU = config.get('MTU', 1500);
MSS = config.get('MSS', 536);
MSL = config.get('MSL', 4800)

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
        self.sport = 0
        self.dport = 0
        self.msl_timeout = 0

    def timeout(self, value = None):
        if value:
            self.msl_timeout = value
        else:
            return self.msl_timeout
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

    def __noop__(self):
        sleep(0.1)

    def __maintenance__(self):
        while True:
            if self.state == self.states.TIME_WAIT:
                if self.tcb.timeout() >= time():
                    print("Connection was closed due to timeout")
                    self.state = self.states.CLOSED
                    self.tcb = None
            elif self.state == self.states.ESTABLISHED:
                currenttime = time()
                for seq in self.send_queue.keys():
                    # Retransmit everything in the queue
                    timestamp, rto, ipv4packet = self.send_queue[seq]
                    if currenttime > rto:
                        self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                        self.send_queue[seq] = (time(), time() + self.rto, ipv4packet)
            elif self.state != self.states.CLOSED and self.tcb:
                self.tcb.timeout(time() + 2 * MSL)

    def __recv__(self):
        while True:
            #print("GOT PACKET")
            buf = bytearray(self.socket.recv(MTU));
            ipv4packet = IPv4Packet(buf)
            if ipv4packet.get_destination_address() != self.src_bytes:
                continue
            tcp_packet = TCPPacket(ipv4packet.get_payload())
            if tcp_packet.get_source_port() != self.dport and tcp_packet.get_destination_port() != self.sport:
                continue
            if self.state == self.states.CLOSED:
                continue
            elif self.state == self.states.CLOSE_WAIT:
                # First check
                not_acceptable = False
                if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                    print("Window is zero and the package is > 0")
                    not_acceptable = True

                if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                    if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                        print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                    if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                        print("Window > 0 plen=0 but the sequance is out of window")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                    if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                            (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                             self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                        print("W>0 plen>0 but the rcv_nxt <= seq < ")
                        not_acceptable = True
                
                if not not_acceptable:
                    continue
                
                # Second check

                if tcp_packet.get_rst_bit():
                    # Clean all queues
                    self.state = self.states.CLOSED
                    self.tcb = None

                # Third check
                if tcp_packet.get_syn_bit():
                    # Send reset packet
                    # Clean all queues
                    self.state = self.states.CLOSED
                    self.tcb = None

            elif self.state == self.states.TIME_WAIT:
                # First check
                not_acceptable = False
                if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                    print("Window is zero and the package is > 0")
                    not_acceptable = True

                if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                    if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                        print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                    if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                        print("Window > 0 plen=0 but the sequance is out of window")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                    if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                            (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                             self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                        print("W>0 plen>0 but the rcv_nxt <= seq < ")
                        not_acceptable = True
                if not not_acceptable:
                    continue
                # Second check

                if tcp_packet.get_rst_bit():
                    self.state = self.states.CLOSED
                    self.tcb = None
                    continue

                # Third check
                if tcp_packet.get_syn_bit():
                    # Send reset packet
                    # Clean all queues
                    self.state = self.states.CLOSED
                    self.tcb = None

            elif self.state == self.states.LAST_ACK:
                not_acceptable = False
                if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                    print("Window is zero and the package is > 0")
                    not_acceptable = True

                if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                    if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                        print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                    if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                        print("Window > 0 plen=0 but the sequance is out of window")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                    if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                            (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                             self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                        print("W>0 plen>0 but the rcv_nxt <= seq < ")
                        not_acceptable = True
                if not not_acceptable:
                    continue

                # Second check

                if tcp_packet.get_rst_bit():
                    self.state = self.states.CLOSED
                    self.tcb = None
                    continue

                # Third check
                if tcp_packet.get_syn_bit():
                    # Send reset packet
                    # Clean all queues
                    self.state = self.states.CLOSED
                    self.tcb = None
                
            elif self.state == self.states.CLOSING:
                not_acceptable = False
                if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                    print("Window is zero and the package is > 0")
                    not_acceptable = True

                if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                    if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                        print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                    if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                        print("Window > 0 plen=0 but the sequance is out of window")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                    if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                            (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                             self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                        print("W>0 plen>0 but the rcv_nxt <= seq < ")
                        not_acceptable = True
                if not not_acceptable:
                    continue
                
                # Second check

                if tcp_packet.get_rst_bit():
                    self.state = self.states.CLOSED
                    self.tcb = None
                    continue

                # Third check
                if tcp_packet.get_syn_bit():
                    # Send reset packet
                    # Clean all queues
                    self.state = self.states.CLOSED
                    self.tcb = None

                if tcp_packet.get_ack_bit():
                    self.state = self.states.TIME_WAIT
            elif self.state == self.states.FIN_WAIT_1:
                # First check
                not_acceptable = False
                if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                    print("Window is zero and the package is > 0")
                    not_acceptable = True

                if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                    if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                        print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                    if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                        print("Window > 0 plen=0 but the sequance is out of window")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                    if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                            (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                             self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                        print("W>0 plen>0 but the rcv_nxt <= seq < ")
                        not_acceptable = True
                if not not_acceptable:
                    continue

                # Second check

                if tcp_packet.get_rst_bit():
                    # Clean all queues
                    self.state = self.states.CLOSED
                    self.tcb = None

                # Third check
                if tcp_packet.get_syn_bit():
                    # Send reset packet
                    # Clean all queues
                    self.state = self.states.CLOSED
                    self.tcb = None

                if tcp_packet.get_ack_bit():
                    self.state = self.states.FIN_WAIT_2
                elif tcp_packet.get_fin_bit():
                    self.state = self.states.CLOSING
                    # Send ACK
            elif self.state == self.states.FIN_WAIT_2:
                # First check
                not_acceptable = False
                if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                    print("Window is zero and the package is > 0")
                    not_acceptable = True

                if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                    if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                        print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                    if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                        print("Window > 0 plen=0 but the sequance is out of window")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                    if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                            (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                             self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                        print("W>0 plen>0 but the rcv_nxt <= seq < ")
                        not_acceptable = True
                if not not_acceptable:
                    continue
                # Second check

                if tcp_packet.get_rst_bit():
                    # Clean all queues
                    self.state = self.states.CLOSED
                    self.tcb = None

                # Third check
                if tcp_packet.get_syn_bit():
                    # Send reset packet
                    # Clean all queues
                    self.state = self.states.CLOSED
                    self.tcb = None

                if tcp_packet.get_fin_bit():
                    self.state = self.states.TIME_WAIT
                    # Send ACK packet
                pass
            elif self.state == self.states.SYN_SENT:
                sequence = tcp_packet.get_sequence_number() + 1
                window = tcp_packet.get_window()

                self.tcb.rcv_nxt = sequence

                if tcp_packet.get_ack_bit():
                    print(tcp_packet.get_acknowledgment_number())
                    if tcp_packet.get_acknowledgment_number() <= self.tcb.iss or tcp_packet.get_acknowledgment_number() > self.tcb.snd_nxt:
                        # Drop the packet and send RST
                        print(tcp_packet.get_acknowledgment_number())
                        print(self.tcb.iss)
                        print(self.tcb.snd_nxt)
                        print("Dropping packet and sending RST")
                        continue
                    if not (tcp_packet.get_acknowledgment_number() >= self.tcb.snd_una and tcp_packet.get_acknowledgment_number() <= self.tcb.snd_nxt):
                        # ACK is not acceptable Drop the packet
                        print(tcp_packet.get_acknowledgment_number())
                        print(self.tcb.snd_una)
                        print(self.tcb.snd_nxt)
                        print("Silently dropping packet")
                        continue
                    if tcp_packet.get_rst_bit():
                        self.state = self.states.CLOSED
                else:
                    if tcp_packet.get_rst_bit():
                        # Drop the packet and return
                        print("RST bit is present... dropping packet")
                        continue
                
                if tcp_packet.get_syn_bit():

                    self.tcb.rcv_nxt = tcp_packet.get_sequence_number() + 1
                    self.tcb.irs = tcp_packet.get_sequence_number()
                    self.tcb.snd_una = tcp_packet.get_acknowledgment_number()
                    self.tcb.snd_wnd = config.get("IW", 4096)
                    self.tcb.rcv_wnd = config.get("IW", 4096)

                    # Remove packets in retransmission queue

                    if self.tcb.snd_una > self.tcb.iss:
                        self.state = self.states.ESTABLISHED
                        print("Moving to established state...")

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
                    print("Sending the ack packet in response to SYN+ACK")
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
                not_acceptable = False
                if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                    print("Window is zero and the package is > 0")
                    not_acceptable = True

                if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                    if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                        print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                    if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                        print("Window > 0 plen=0 but the sequance is out of window")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                    if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                            (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                             self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                        print("W>0 plen>0 but the rcv_nxt <= seq < ")
                        not_acceptable = True
                    
                if not_acceptable:
                    print("Not acceptable data received")
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

                # Forth check
                if tcp_packet.get_syn_bit():
                    # Send reset packet
                    # Clean all queues
                    self.state = self.states.CLOSED
                    self.tcb = None
                
                # Fifth check
                if not tcp_packet.get_ack_bit():
                    # Drop the packet and return
                    continue

                if tcp_packet.get_ack_bit():
                    if self.tcb.snd_una < tcp_packet.get_acknowledgment_number() and tcp_packet.get_acknowledgment_number()<= self.tcb.snd_nxt:
                        self.tcb.snd_una = tcp_packet.get_acknowledgment_number()

                        # Remove the packets that have sequnce <= self.tcb.snd_una
                        #seqs = list(self.send_queue.keys())
                        #for seq in seqs:
                        #    if seq <= self.tcb.snd_una:
                        #        del self.send_queue[seq]
                        #        print("Deleting packets from the send queue")
                        del self.send_queue[tcp_packet.get_acknowledgment_number()]

                        # Move those packets to the user's queue
                        #Update the window
                        if self.tcb.snd_wl1 < tcp_packet.get_sequence_number() or \
                            (self.tcb.snd_wl1 == tcp_packet.get_sequence_number() and \
                             self.tcb.snd_wl2 <= tcp_packet.get_acknowledgment_number()):
                            self.tcb.snd_wnd = tcp_packet.get_window()
                            self.tcb.snd_wl1 = tcp_packet.get_sequence_number()
                            self.tcb.snd_wl2 = tcp_packet.get_acknowledgment_number()
                    # Duplicate aCK
                    if tcp_packet.get_acknowledgment_number() < self.tcb.snd_una:
                        print("Duplicate ACK... ignoring...")
                        continue
                    if tcp_packet.get_acknowledgment_number() > self.tcb.snd_nxt:
                        # Send ACK and drop the packet
                        print("ACK is not acknowledging anything... sending ACK in response")
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

                if len(tcp_packet.get_data()) > 0:
                    print(tcp_packet.get_data())
                    self.receive_queue[tcp_packet.get_sequence_number()] = (time(), ipv4packet)

                # Advance the RCV_NXT
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
                
                continue;
            elif self.state == self.states.LISTEN:
                if tcp_packet.get_syn_bit():
                    # Send SYN+ACK
                    self.state = self.states.SYN_RECEIVED
            elif self.state == self.states.SYN_RECEIVED:
                # Second check
                not_acceptable = False
                if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                    print("Window is zero and the package is > 0")
                    not_acceptable = True

                if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                    if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                        print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                    if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                        print("Window > 0 plen=0 but the sequance is out of window")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                    if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                            (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                             self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                        print("W>0 plen>0 but the rcv_nxt <= seq < ")
                        not_acceptable = True
                if not not_acceptable:
                    continue
                
                # Second check
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
                    # Clean all queues
                    self.state = self.states.CLOSED
                    self.tcb = None

                if tcp_packet.get_ack_bit():
                    self.state = self.states.ESTABLISHED
            elif self.state == self.states.LAST_ACK:
                # First check
                not_acceptable = False
                if (self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) > 0):
                    print("Window is zero and the package is > 0")
                    not_acceptable = True

                if self.tcb.rcv_wnd == 0 and len(tcp_packet.get_data()) == 0:
                    if tcp_packet.get_sequence_number() != self.tcb.rcv_nxt:
                        print("Window is zero and the packet length is zero, but the tcp_packet.sequence is not equal to rcv_nxt")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) == 0:
                    if not (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd):
                        print("Window > 0 plen=0 but the sequance is out of window")
                        not_acceptable = True

                if self.tcb.rcv_wnd > 0 and len(tcp_packet.get_data()) > 0:
                    if not ((self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() and tcp_packet.get_sequence_number() < self.tcb.rcv_nxt + self.tcb.rcv_wnd) or \
                            (self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) and \
                             self.tcb.rcv_nxt <= tcp_packet.get_sequence_number() + len(tcp_packet.get_data()) < self.tcb.rcv_nxt + self.tcb.rcv_wnd)):
                        print("W>0 plen>0 but the rcv_nxt <= seq < ")
                        not_acceptable = True
                if not not_acceptable:
                    continue
                
                # Second check
                if tcp_packet.get_ack_bit():
                    self.state = self.states.CLOSED
                    self.tcb = None

                # Third check
                if tcp_packet.get_syn_bit():
                    # Send reset packet
                    # Clean all queues
                    self.state = self.states.CLOSED
                    self.tcb = None
            
    def __send__(self):
        while True:
            if self.state == self.states.CLOSED:
                print("Sending packet...")
                self.tcb = TransmissionControlBlock()
                self.tcb.iss = TCPUtils.generate_isn()
                self.tcb.snd_una = self.tcb.iss
                self.tcb.snd_nxt = self.tcb.iss + 1
                print("Setting TCB ISS")
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

                self.state = self.states.SYN_SENT
            
            elif self.state == self.states.ESTABLISHED:
                
                plen = MSS
                if len(self.data_to_send) < MSS:
                    plen = len(self.data_to_send)
                if plen == 0:
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

                
                # Put into the send queue timestamp, RTO, ipv4packet
                self.send_queue[self.tcb.rcv_nxt] = (time(), time() + self.rto, ipv4packet)
                
                self.tcb.snd_nxt += plen
                self.socket.sendto(ipv4packet.get_buffer(), (self.dst, 0))
                self.__noop__()
            elif self.state == self.states.LISTEN:
                # Send SYN packet
                pass

    def open(self, src, dst, src_port, dst_port, listen = False):
        
        self.src = src
        self.dst = dst
        self.src_bytes = Misc.ipv4_address_to_bytes(src)
        self.dst_bytes = Misc.ipv4_address_to_bytes(dst)
        self.sport = src_port
        self.dport = dst_port
        
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
        
        #self.tcb = TransmissionControlBlock()
        #self.tcb.cwnd = config.get("IW", 4096)

        self.states = TCPStates()
        if listen:
            self.state = self.states.LISTEN
        else:
            self.state = self.states.CLOSED
        
    def send(self, data):
        self.data_to_send += bytearray(data)

    def receive(self, len):
        if len(self.received_data) >= len:
            buf = self.received_data[:len]
            self.received_data = self.received_data[len:]
            return buf
    def close(self):
        # Send FIN packet
        if self.state == self.states.CLOSE_WAIT:
            self.state = self.states.LAST_ACK
            # send FIN packet
            pass
        elif self.state == self.states.SYN_SENT:
            self.state = self.states.CLOSED
            self.tcb = None
        elif self.state == self.states.SYN_RECEIVED:
            self.state = self.states.FIN_WAIT_1
            # Send FIN packet
        elif self.state == self.states.LISTEN:
            self.state = self.states.CLOSED
            self.tcb = None
        elif self.state == self.states.ESTABLISHED:
            # send FIN packet
            self.state = self.states.FIN_WAIT_1
    def abort(self):
        pass
    def status(self):
        pass
    
