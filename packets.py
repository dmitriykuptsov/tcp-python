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
    def set_payliad(self, payload):
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
WINDOW_LENGTH = 0x1
CHECKSUM_OFFSET = 0x1
CHECKSUM_LENGTH = 0x2
URGENT_POINTER_OFFSET = 0x12
URGENT_POINTER_LENGTH = 0x2
OPTIONS_OFFSET = 0x18

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
    