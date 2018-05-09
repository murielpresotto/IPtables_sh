#!/bin/bash
https()
	{
		iptables -A OUTPUT -p 6 -s 10.0.2.15 --sport 1024:65535 -d 0/0 --dport 80 -j ACCEPT
		iptables -A OUTPUT -p 6 -s 10.0.2.15 --sport 1024:65535 -d 0/0 --dport 443 -j ACCEPT

		iptables -A INPUT -p 6 -s 0/0 --sport 80 -d 10.0.2.15 --dport 1024:65535 -j ACCEPT
		iptables -A INPUT -p 6 -s 0/0 --sport 443 -d 10.0.2.15 --dport 1024:65535 -j ACCEPT
	}
https
