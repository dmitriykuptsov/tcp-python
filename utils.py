
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
            sum += (((buffer[i] << 8) & 0xFFFF) | (buffer[i + 1] & 0xFF))
        if len(buffer) % 2 != 0:
            sum += ((buffer[len(buffer) - 1] << 8) & 0xFFFF)
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