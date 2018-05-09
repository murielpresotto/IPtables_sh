#!/bin/bash
pre_nat()
	{
		iptables -t nat -A PREROUTING -p tcp -s 0/0 -d 10.11.1.185 --dport 22 -j DNAT --to 192.168.200.1:52000
	}
pre_nat
