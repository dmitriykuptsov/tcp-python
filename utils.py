
#!/usr/bin/python

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

import packets

class Checksum():
    @staticmethod
    def checksum(buffer):
        """
        Computes checksum
        """
        sum = 0;
        if len(buffer) % 2 == 0:
            buffer_len = len(buffer)
        else:
            buffer_len = len(buffer) - 1
        for i in range(0, buffer_len, 2):
            sum += (((buffer[i] << 8) & 0xFF00) | (buffer[i + 1] & 0xFF))
        if len(buffer) % 2 != 0:
            sum += ((buffer[len(buffer) - 1] << 8) & 0xFF00)
        sum =  (sum >> 16) + (sum & 0xffff);
        sum += (sum >> 16);
        return ~sum;

    @staticmethod
    def verify_checksum(buffer, checksum):
        """
        Verifies the checksum
        """
        computed_checksum = (Checksum.icmp_checksum(buffer) & 0XFFFF);
        return computed_checksum == checksum;

class Misc():
    @staticmethod
    def ipv4_address_to_bytes(address):
        buf = bytearray([0] * 4)
        parts = address.split(".")
        buf[0] = int(parts[0]) & 0xFF
        buf[1] = int(parts[1]) & 0xFF
        buf[2] = int(parts[2]) & 0xFF
        buf[3] = int(parts[3]) & 0xFF
        return buf
    @staticmethod
    def bytes_to_ipv4_string(address):
        return str(address[0]) + "." + str(address[1]) + "." + \
            str(address[2]) + "." + str(address[3])
    @staticmethod
    def ipv4_address_to_int(address):
        parts = address.split(".")
        addr = (int(parts[0]) & 0xFF << 24)
        addr |= (int(parts[1]) & 0xFF << 16)
        addr |= (int(parts[2]) & 0xFF << 8)
        addr |= (int(parts[3]) & 0xFF)
        return addr
    
    @staticmethod
    def port_to_bytes(port):
        buf = bytearray([0, 0])
        buf[0] = ((port >> 8) & 0xFF)
        buf[1] = (port & 0xFF)
        return buf
    
    @staticmethod
    def int_to_bytes(value):
        buf = bytearray([0, 0])
        buf[0] = ((value >> 8) & 0xFF)
        buf[1] = (value & 0xFF)
        return buf
    
    @staticmethod
    def make_pseudo_header(src, dst, length):
        return bytearray(src + dst + bytearray([0]) + bytearray([packets.TCP_PROTOCOL_NUMBER]) + length)

import os
import hashlib

class TCPUtils():
    @staticmethod
    def generate_isn(clock, localip, remoteip, localport, remoteport):
        secret = os.urandom(16)
        sha1 = hashlib.sha1()
        sha1.update(secret)
        sha1.update(localip.encode('ascii'))
        sha1.update(str(localport).encode('ascii'))
        sha1.update(remoteip.encode('ascii'))
        sha1.update(remoteip.encode('ascii'))
        sha1.update(str(remoteport).encode('ascii'))
        isn = sha1.digest()
        isn = int.from_bytes(isn, byteorder="big")
        return (clock + isn) % (2**32 -1)