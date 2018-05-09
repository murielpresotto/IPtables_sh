#!/bin/bash
ping ()
	{
		iptables -A INPUT -p icmp --icmp-type 0 -s 0/0 -d 10.0.2.15 -j ACCEPT
		iptables -A OUTPUT -p icmp --icmp-type 8 -s 10.0.2.15 -d 0/0 -j ACCEPT
	}
ping
