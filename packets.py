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

class Packet():
    pass


IPV4_PACKET_LENGTH = 0x14;
IPV4_VERSION_OFFSET = 0x0
IPV4_IHL_OFFSET = 0x0
IPV4_TYPE_OF_SERVICE_LENGTH = 0x1
IPV4_TYPE_OF_SERVICE_OFFSET = 0x1
IPV4_TOTAL_LENGTH_LENGTH = 0x2
IPV4_TOTAL_LENGTH_OFFSET = 0x2
IPV4_IDENTIFICATION_LENGTH = 0x2
IPV4_IDENTIFICATION_OFFSET = 0x4
IPV4_FLAGS_OFFSET = 0x6
IPV4_FRAGMENT_OFFSET = 0x6
IPV4_TTL_OFFSET = 0x8
IPV4_PROTOCOL_OFFSET = 0x9
IPV4_CHECKSUM_OFFSET = 0xA
IPV4_SRC_ADDRESS_OFFSET = 0xC
IPV4_SRC_ADDRESS_LENGTH = 0x4
IPV4_DST_ADDRESS_OFFSET = 0x10
IPV4_DST_ADDRESS_LENGTH = 0x4
IPV4_VERSION = 0x4
IPV4_LENGTH = 0x5
class IPv4Packet(Packet):
    def __init__(self, buffer = None):
        if not buffer:
            self.buffer = bytearray([0]) * IPV4_PACKET_LENGTH
            self.buffer[IPV4_VERSION_OFFSET] = (IPV4_VERSION << 4) | (IPV4_LENGTH & 0xF)
        else:
            self.buffer = buffer
    def set_total_length(self, length):
        self.buffer[IPV4_TOTAL_LENGTH_OFFSET] = (length >> 8) & 0xFF
        self.buffer[IPV4_TOTAL_LENGTH_OFFSET + 1] = (length & 0xFF)
    def get_total_length(self):
        length = self.buffer[IPV4_TOTAL_LENGTH_OFFSET]
        length |= self.buffer[IPV4_TOTAL_LENGTH_OFFSET + 1]
        return length
    def set_ttl(self, ttl):
        self.buffer[IPV4_TTL_OFFSET] = ttl & 0xFF
    def get_ttl(self):
        return self.buffer[IPV4_TTL_OFFSET]
    def set_protocol(self, protocol):
        self.buffer[IPV4_PROTOCOL_OFFSET] = protocol & 0xFF
    def get_protocol(self):
        return self.buffer[IPV4_PROTOCOL_OFFSET]
    def set_checksum(self, checksum):
        self.buffer[IPV4_CHECKSUM_OFFSET] = (checksum >> 8) & 0xFF
        self.buffer[IPV4_CHECKSUM_OFFSET + 1] = (checksum & 0xFF)
    def get_checksum(self):
        checksum = self.buffer[IPV4_CHECKSUM_OFFSET]
        checksum |= self.buffer[IPV4_CHECKSUM_OFFSET + 1]
        return checksum
    def set_source_address(self, src):
        self.buffer[IPV4_SRC_ADDRESS_OFFSET:IPV4_SRC_ADDRESS_OFFSET + IPV4_SRC_ADDRESS_LENGTH] = src 
    def get_source_address(self):
        return self.buffer[IPV4_SRC_ADDRESS_OFFSET:IPV4_SRC_ADDRESS_OFFSET + IPV4_SRC_ADDRESS_LENGTH]
    def set_destination_address(self, dst):
        self.buffer[IPV4_DST_ADDRESS_OFFSET:IPV4_DST_ADDRESS_OFFSET + IPV4_DST_ADDRESS_LENGTH] = dst 
    def get_destination_address(self):
        return self.buffer[IPV4_DST_ADDRESS_OFFSET:IPV4_DST_ADDRESS_OFFSET + IPV4_DST_ADDRESS_LENGTH]
    def set_payload(self, payload):
        self.buffer = self.buffer + payload
    def get_payload(self):
        return self.buffer[IPV4_DST_ADDRESS_OFFSET + IPV4_DST_ADDRESS_LENGTH:]
    def get_header(self):
        return self.buffer[:IPV4_DST_ADDRESS_OFFSET + IPV4_DST_ADDRESS_LENGTH]
    def get_buffer(self):
        return self.buffer
    
SOURCE_PORT_OFFSET = 0x0
SOURCE_PORT_LENGTH = 0x2
DESTINATION_PORT_OFFSET = 0x2
DESTINATION_PORT_LENGTH = 0x2
SEQUENCE_NUMBER_OFFSET = 0x4
SEQUENCE_NUMBER_LENGTH = 0x4
ACKNOWLEDGEMENT_NUMBER_OFFSET = 0x8
ACKNOWLEDGEMENT_NUMBER_LENGTH = 0x4
DATA_OFFSET_OFFSET = 0xC
DATA_OFFSET_LENGTH = 0x1
RESERVED_LENGTH = 0x1
FLAGS_OFFSET = 0xD
FLAGS_LENGTH = 0x1
WINDOW_OFFSET = 0xE
WINDOW_LENGTH = 0x2
CHECKSUM_OFFSET = 0x10
CHECKSUM_LENGTH = 0x2
URGENT_POINTER_OFFSET = 0x12
URGENT_POINTER_LENGTH = 0x2
OPTIONS_OFFSET = 0x18

TCP_PROTOCOL_NUMBER = 6
IP_DEFAULT_TTL = 128

"""
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Acknowledgment Number                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Data |       |C|E|U|A|P|R|S|F|                               |
   | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
   |       |       |R|E|G|K|H|T|N|N|                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Checksum            |         Urgent Pointer        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           [Options]                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               :
   :                             Data                              :
   :                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""

class TCPPacket(Packet):
    def __init__(self, buffer = None):
        if buffer is None:
            self.buffer = bytearray([0] * (SOURCE_PORT_LENGTH + \
                                            DESTINATION_PORT_LENGTH + \
                                                SEQUENCE_NUMBER_LENGTH + \
                                                    ACKNOWLEDGEMENT_NUMBER_LENGTH + \
                                                        DATA_OFFSET_LENGTH + \
                                                            FLAGS_LENGTH + \
                                                                WINDOW_LENGTH + \
                                                                    CHECKSUM_LENGTH + \
                                                                        URGENT_POINTER_LENGTH))
        else:
            self.buffer = bytearray(buffer)
    def get_source_port(self):
        port = 0
        port = (self.buffer[SOURCE_PORT_OFFSET] << 8)
        port |= self.buffer[SOURCE_PORT_OFFSET + 1]
        return port
    def set_source_port(self, port):
        self.buffer[SOURCE_PORT_OFFSET] = (port >> 8) & 0xFF
        self.buffer[SOURCE_PORT_OFFSET + 1] = port & 0xFF
    def get_destination_port(self):
        port = 0
        port = (self.buffer[DESTINATION_PORT_OFFSET] << 8)
        port |= self.buffer[DESTINATION_PORT_OFFSET + 1]
        return port
    def set_destination_port(self, port):
        self.buffer[DESTINATION_PORT_OFFSET] = (port >> 8) & 0xFF
        self.buffer[DESTINATION_PORT_OFFSET + 1] = port & 0xFF
    def get_sequence_number(self):
        seq = 0
        seq = (self.buffer[SOURCE_PORT_OFFSET] << 24)
        seq |= (self.buffer[SOURCE_PORT_OFFSET + 1] << 16)
        seq |= (self.buffer[SOURCE_PORT_OFFSET + 2] << 8)
        seq |= (self.buffer[SOURCE_PORT_OFFSET + 3])
        return seq
    def set_sequence_number(self, seq):
        self.buffer[SEQUENCE_NUMBER_OFFSET] = (seq >> 24) & 0xFF
        self.buffer[SEQUENCE_NUMBER_OFFSET + 1] = (seq >> 16) & 0xFF
        self.buffer[SEQUENCE_NUMBER_OFFSET + 2] = (seq >> 8) & 0xFF
        self.buffer[SEQUENCE_NUMBER_OFFSET + 3] = seq & 0xFF
    def get_data_offset(self):
        return (self.buffer[DATA_OFFSET_OFFSET] & 0xF0) >> 4
    def set_data_offset(self, offset):
        self.buffer[DATA_OFFSET_OFFSET] = (offset << 4) & 0xFF
    def get_flags(self):
        return self.buffer[FLAGS_OFFSET]
    def get_cwr_bit(self):
        return (self.buffer[FLAGS_OFFSET] & 0x80) >> 7
    def get_ecu_bit(self):
        return (self.buffer[FLAGS_OFFSET] & 0x40) >> 6
    def get_urg_bit(self):
        return (self.buffer[FLAGS_OFFSET] & 0x20) >> 5
    def get_ack_bit(self):
        return (self.buffer[FLAGS_OFFSET] & 0x10) >> 4
    def get_psh_bit(self):
        return (self.buffer[FLAGS_OFFSET] & 0x8) >> 3
    def get_rst_bit(self):
        return (self.buffer[FLAGS_OFFSET] & 0x4) >> 2
    def get_syn_bit(self):
        return (self.buffer[FLAGS_OFFSET] & 0x2) >> 1
    def get_fin_bit(self):
        return self.buffer[FLAGS_OFFSET] & 0x1
    def set_cwr_bit(self, flag):
        flag = (flag & 0x1)
        self.buffer[FLAGS_OFFSET] = (self.buffer[FLAGS_OFFSET] | (flag << 7))
    def set_ecu_bit(self, flag):
        flag = (flag & 0x1)
        self.buffer[FLAGS_OFFSET] = (self.buffer[FLAGS_OFFSET] | (flag << 6))
    def set_urg_bit(self, flag):
        flag = (flag & 0x1)
        self.buffer[FLAGS_OFFSET] = (self.buffer[FLAGS_OFFSET] | (flag << 5))
    def set_ack_bit(self, flag):
        flag = (flag & 0x1)
        self.buffer[FLAGS_OFFSET] = (self.buffer[FLAGS_OFFSET] | (flag << 4))
    def set_psh_bit(self, flag):
        flag = (flag & 0x1)
        self.buffer[FLAGS_OFFSET] = (self.buffer[FLAGS_OFFSET] | (flag << 3))
    def set_rst_bit(self, flag):
        flag = (flag & 0x1)
        self.buffer[FLAGS_OFFSET] = (self.buffer[FLAGS_OFFSET] | (flag << 2))
    def set_syn_bit(self, flag):
        flag = (flag & 0x1)
        self.buffer[FLAGS_OFFSET] = (self.buffer[FLAGS_OFFSET] | (flag << 1))
    def set_fin_bit(self, flag):
        flag = (flag & 0x1)
        self.buffer[FLAGS_OFFSET] = (self.buffer[FLAGS_OFFSET] | (flag << 0))
    def get_window(self):
        window = 0
        window = (self.buffer[WINDOW_OFFSET] << 8)
        window |= self.buffer[WINDOW_OFFSET + 1]
        return window
    def set_window(self, window):
        self.buffer[WINDOW_OFFSET] = (window >> 8) & 0xFF
        self.buffer[WINDOW_OFFSET + 1] = window & 0xFF
    def set_checksum(self, checksum):
        self.buffer[CHECKSUM_OFFSET] = (checksum >> 8) & 0xFF
        self.buffer[CHECKSUM_OFFSET + 1] = (checksum & 0xFF)
    def get_checksum(self):
        checksum = 0
        checksum |= (self.buffer[CHECKSUM_OFFSET] << 8)
        checksum |= (self.buffer[CHECKSUM_OFFSET + 1])
        return checksum
    def set_sequence_number(self, sequence):
        self.buffer[SEQUENCE_NUMBER_OFFSET] = (sequence >> 24) & 0xFF
        self.buffer[SEQUENCE_NUMBER_OFFSET + 1] = (sequence >> 16) & 0xFF
        self.buffer[SEQUENCE_NUMBER_OFFSET + 2] = (sequence >> 8) & 0xFF
        self.buffer[SEQUENCE_NUMBER_OFFSET + 3] = sequence & 0xFF
    def get_sequence_number(self):
        sequence = 0
        sequence = (self.buffer[SEQUENCE_NUMBER_OFFSET] << 24)
        sequence |= (self.buffer[SEQUENCE_NUMBER_OFFSET + 1] << 16)
        sequence |= (self.buffer[SEQUENCE_NUMBER_OFFSET + 2] << 8)
        sequence |= (self.buffer[SEQUENCE_NUMBER_OFFSET + 3])
        return sequence
    def set_acknowledgment_number(self, sequence):
        self.buffer[ACKNOWLEDGEMENT_NUMBER_OFFSET] = (sequence >> 24) & 0xFF
        self.buffer[ACKNOWLEDGEMENT_NUMBER_OFFSET + 1] = (sequence >> 16) & 0xFF
        self.buffer[ACKNOWLEDGEMENT_NUMBER_OFFSET + 2] = (sequence >> 8) & 0xFF
        self.buffer[ACKNOWLEDGEMENT_NUMBER_OFFSET + 3] = sequence & 0xFF
    def get_acknowledgment_number(self):
        sequence = 0
        sequence = (self.buffer[ACKNOWLEDGEMENT_NUMBER_OFFSET] << 24)
        sequence |= (self.buffer[ACKNOWLEDGEMENT_NUMBER_OFFSET + 1] << 16)
        sequence |= (self.buffer[ACKNOWLEDGEMENT_NUMBER_OFFSET + 2] << 8)
        sequence |= (self.buffer[ACKNOWLEDGEMENT_NUMBER_OFFSET + 3])
        return sequence
    def get_urgent_pointer(self):
        pointer = 0
        pointer |= (self.buffer[URGENT_POINTER_OFFSET] << 8)
        pointer |= (self.buffer[URGENT_POINTER_OFFSET + 1])
        return pointer
    def set_urgent_pointer(self, pointer):
        self.buffer[URGENT_POINTER_OFFSET] = (pointer >> 8) & 0xFF
        self.buffer[URGENT_POINTER_OFFSET + 1] = pointer & 0xFF
    def get_options(self):
        if self.get_data_offset() == 5:
            return []
        has_more_options = True
        offset = 5 * 4
        options = []
        while has_more_options:
            if self.buffer[offset] == TCP_OPTION_END_OF_OPTION_KIND:
                has_more_options = False
                option = TCPOption()
                option.set_kind(TCP_OPTION_END_OF_OPTION_KIND)
                options.append(option)
            elif self.buffer[offset] == TCP_NOOP_OPTION_KIND:
                option = TCPOption()
                option.set_kind(TCP_NOOP_OPTION_KIND)
                options.append(option)
                offset += 1
            elif self.buffer[offset] == TCP_MSS_OPTION_KIND:
                buf = self.buffer[offset:offset+4]
                option = TCPMSSOption(buf)
                options.append(option)
                offset += 4
    def set_options(self, options):
        total_length = 0
        for o in options:
            total_length += len(o.get_buffer())
        
        padding = bytearray([])
        if total_length % 4 != 0:
            padding_length = (total_length % 4)
            total_length += padding_length
            padding = bytearray([0] * padding_length)
        for o in options:
            self.buffer += o.get_buffer()

        self.buffer += padding
        self.set_data_offset(int(self.get_data_offset() + total_length / 4))

    def set_data(self, data):
        offset = self.get_data_offset() * 4
        self.buffer[offset:offset + len(data)] = data
    def get_data(self):
        offset = self.get_data_offset() * 4
        return self.buffer[offset:]
    def get_buffer(self):
        return self.buffer


TCP_OPTION_END_OF_OPTION_KIND = 0x0
TCP_NOOP_OPTION_KIND = 0x1
TCP_MSS_OPTION_KIND = 0x2

TCP_OPTION_KIND_OFFSET = 0x0;
TCP_OPTION_KIND_LENGTH = 0x1;

class TCPOption():
    def __init__(self, buffer = None):
        if not buffer:
            self.buffer = bytearray([0] * TCP_OPTION_KIND_LENGTH)
        else:
            self.buffer = buffer;
    def get_kind(self):
        return self.buffer[TCP_OPTION_KIND_OFFSET]
    def set_kind(self, kind):
        self.buffer[TCP_OPTION_KIND_OFFSET] = kind
    def get_buffer(self):
        return self.buffer;

TCP_MSS_OPTION_LENGTH = 0x1
TCP_MSS_OPTION_LENGTH_OFFSET = 0x1
TCP_MSS_OPTION_LENGTH_LENGTH = 0x1
TCP_MSS_OPTION_VALUE_LENGTH = 0x2
TCP_MSS_OPTION_VALUE_OFFSET = 0x2

class TCPMSSOption(TCPOption):
    def __init__(self, buffer = None):
        if not buffer:
            self.buffer = bytearray([0] * (TCP_OPTION_KIND_LENGTH + \
                                            TCP_MSS_OPTION_LENGTH_LENGTH + \
                                                TCP_MSS_OPTION_VALUE_LENGTH))
            self.buffer[TCP_MSS_OPTION_LENGTH_OFFSET] = 0x4
        else:
            self.buffer = buffer;
    def get_length(self):
        return 0x4
    def get_mss(self):
        mss = 0
        mss = (self.buffer[TCP_MSS_OPTION_VALUE_OFFSET] << 8) & 0xFF
        mss |= (self.buffer[TCP_MSS_OPTION_VALUE_OFFSET + 1]) & 0xFF
        return mss
    def set_mss(self, mss):
        self.buffer[TCP_MSS_OPTION_VALUE_OFFSET] = (mss >> 8) & 0xFF
        self.buffer[TCP_MSS_OPTION_VALUE_OFFSET + 1] = (mss & 0xFF)