# TCP implementaion in Python

This repository implements TCP protocol using Python language.

To test the implmentation of TCP we have created a simple network cat utitlity.

# Usage

Netcat in server mode
```
$ python nc.py -l host port
```

Netcat in client mode

```
$ python nc.py host port
```

Prevent Linux kernel from replying to custom TCP handshake
```
$ sudo iptables -i lo -t raw -A PREROUTING -p tcp --dport 45000 -j DROP
```