#!/bin/bash
tcp_cliente()
	
		for portas in $(cat /etc/firewall/portas_tcp.txt)
		do
			iptables -A INPUT -p tcp -d 0/0 --dport 1024:65535 -s 10.0.2.15 --sport $portas -j ACCEPT
			iptables -A OUTPUT -p tcp -s 10.0.2.15 --sport 1024:65535 -d 0/0 --dport $portas -j ACCEPT
	

	done
tcp_cliente
