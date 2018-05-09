#!/bin/bash
mtr()
	{
		iptables -A INPUT -p icmp --icmp-type 11 -s 0/0 -d 10.0.2.15 -j ACCEPT
	}
mtr
