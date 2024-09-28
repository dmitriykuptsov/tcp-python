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
# Threading
import threading
# System calls
import sys

parser = argparse.ArgumentParser(
                        prog='nc',
                        description='Netcat for sending raw bytes over the network to the remote machine')

parser.add_argument("--src", dest="src", required=True, help="Source address")
parser.add_argument("--dst", dest="dst", required=False, help="Destination address")
parser.add_argument("--source-port", dest="sport", required=True, help="Source port", type=int)
parser.add_argument("--destination-port", dest="dport", required=False, help="Destination port", type=int)
parser.add_argument("-l", required=False, help="Listen mode", action="store_true")
args = parser.parse_args()

tcp = TCP()

if not args.l:
    args.l = False

# Open TCP channel
tcp.open(args.src, args.dst, args.sport, args.dport, listen=args.l)

if args.l:
    tcp.listen()

main_loop_liveness = True
# Receive loop
def __recv__():
    while True:
        buf = tcp.receive(100)
        if buf:
            s = "".join(map(chr, list(buf)))
            sys.stdout.write("%s\n> "  % (s.strip()))
# Send loop
def __send__():
    global main_loop_liveness
    while True:
        sys.stdout.write("> ")
        sys.stdout.flush()
        s = sys.stdin.readline()
        data = s.encode("ascii")
        if s.strip() == "exit":
            tcp.close()
            main_loop_liveness = False
            continue
        if s.strip() == "status":
            print(tcp.status().strip())
            continue
        tcp.send(data)

recv_thread = threading.Thread(target = __recv__, args = (), daemon = True);
send_thread = threading.Thread(target = __send__, args = (), daemon = True);

recv_thread.start()
send_thread.start()

while main_loop_liveness:
    # Main loop
    sleep(1)