#!/bin/bash
icmps()
	{
		for tipo in 0 3/0 3/1 3/2 3/3 3/4 4 5 11 12
		do
			iptables -A INPUT -p icmp -s 0/0 -d 10.0.2.15 --icmp-type $tipo -m limit --limit 1/s -j ACCEPT
		done
		iptables -A OUTPUT -p icmp --icmp-type 8 -s 10.0.2.15 -d 0/0 -j ACCEPT
	}
icmps
