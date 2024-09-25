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

from packets import *
from tcp import *
from utils import TCPUtils
from time import sleep
tcp = TCP()
tcp.open("127.0.0.1", "127.0.0.1", 45000, 1001, listen=False)
#print(TCPUtils.generate_isn(0, "localhost", "localhost", 22, 45000))0
print("------------------------------------------")
tcp.send(bytearray([ord("H"), ord("E"), ord("L"), ord("L"), ord("O"), ord(" "), ord("W"), ord("O"), ord("R"), ord("L"), ord("D"), ord("\n")]))
sleep(5)
tcp.send(bytearray([ord("H"), ord("E"), ord("L"), ord("L"), ord("O"), ord(" "), ord("W"), ord("O"), ord("R"), ord("L"), ord("D"), ord("\n")]))
while True:
    print("SEND LOOP")
    #tcp.send(bytearray([chr("H"), chr("E"), chr("L"), chr("L"), chr("O")]))
    sleep(1)