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

__author__ = "Dmitriy Kuptsov"
__copyright__ = "Copyright 2024, strangebit"
__license__ = "GPL"
__version__ = "0.0.1b"
__maintainer__ = "Dmitriy Kuptsov"
__email__ = "dmitriy.kuptsov@strangebit.io"
__status__ = "development"

# TCP and IP packets
from packets import *
# TCP implmentation
from tcp import *
# TCP utilities
from utils import TCPUtils
# Timing
from time import sleep
# Arguments parser
import argparse


parser = argparse.ArgumentParser(
                        prog='nc',
                        description='Netcat for sending raw bytes over the network to the remote machine')

parser.add_argument("--src", dest="src", required=True, help="Source address")
parser.add_argument("--dst", dest="dst", required=True, help="Destination address")
parser.add_argument("--source-port", dest="sport", required=True, help="Source port", type=int)
parser.add_argument("--destination-port", dest="dport", required=True, help="Destination port", type=int)
parser.add_argument("-l", required=True, help="Listen mode", action="store_true")
args = parser.parse_args()

tcp = TCP()
tcp.open(args.src, args.dst, args.sport, args.dport, listen=args.l)
#print(TCPUtils.generate_isn(0, "localhost", "localhost", 22, 45000))0
print("------------------------------------------")
tcp.send(bytearray([ord("H"), ord("E"), ord("L"), ord("L"), ord("O"), ord(" "), ord("W"), ord("O"), ord("R"), ord("L"), ord("D"), ord("\n")]))
sleep(5)
tcp.send(bytearray([ord("H"), ord("E"), ord("L"), ord("L"), ord("O"), ord(" "), ord("W"), ord("O"), ord("R"), ord("L"), ord("D"), ord("\n")]))
while True:
    #print("SEND LOOP")
    #tcp.send(bytearray([chr("H"), chr("E"), chr("L"), chr("L"), chr("O")]))
    sleep(1)