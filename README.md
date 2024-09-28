# TCP implementaion in Python

This repository implements TCP protocol using Python language.

To test the implmentation of TCP we have created a simple network cat utitlity.

# Usage

Netcat in server mode
```
$ sudo python3 nc.py --src [src] --source-port [sport] -l
```

Netcat in client mode

```
$ sudo python3 nc.py --src [src] --dst [dst] --source-port [sport] --destination-port [dport]
```

Prevent Linux kernel from replying to custom TCP handshake
```
$ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

Simulate packet drop on loopback interface
```
$ sudo tc qdisc add dev lo root netem loss 50% delay 300 100
```