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
    def open(self, src, dst, src_port, dst_port, listen = False):
        pass
    def send(self, data):
        pass
    def receive(self):
        pass
    def close(self):
        pass
    def abort(self):
        pass
    def status(self):
        pass
    
