#!/bin/bash
iptables -N ALLOW_ICMP
icmp_chain()
	{
		iptables -A ALLOW_ICMP -m limit --limit 1/s -j ACCEPT
		for TIPO in 0 3/0 3/1 3/2 3/3 3/4 4 5 11 12
		do
			iptables -A INPUT -p 1 -s 0/0 -d 10.0.2.15 --icmp-type $TIPO -j ALLOW_ICMP
		done
			iptables -A OUTPUT -p 1 -d 0/0 -s 10.0.2.15 --icmp-type 8 -j ALLOW_ICMP
	}
	icmp_chain
