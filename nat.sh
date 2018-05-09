#!/bin/bash
nat()
	
	{
		iptables -A FORWARD -s 0/0 -d 192.168.200.0/24 -j ACCEPT
		iptables -A FORWARD -s 192.168.200.0/24 -d 0/0 -j ACCEPT
	
		iptables -t nat -A POSTROUTING -s 192.168.200.0/24 -o eth0 -j MASQUERADE
	}
nat
