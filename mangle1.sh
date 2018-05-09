#!/bin/bash
mangle()
	{
		##Entrada para Servidor Web
		iptables -t mangle -A PREROUTING -i eth0 -p tcp --sport 443 -j TOS --set-tos 16
		iptables -t mangle -A PREROUTING -i eth1 -p tcp --sport 443 -j TOS --set-tos 16

		##Entrada para servidor de email
		iptables -t mangle -A PREROUTING -i eth1 -p tcp --sport 25 -j TOS --set-tos 16

		##Saida para Servidor WEB
		iptables -t mangle -A OUTPUT -o eth0 -p tcp --dport 443 -j TOS --set-tos 16
		iptables -t mangle -A OUTPUT -o eth1 -p tcp --dport 443 -j TOS --set-tos 16

		##Saida para Servidor de email
		iptables -t mangle -A OUTPUT -o eth1 -p tcp --dport 25 -j TOS --set-tos 16 
	}
mangle
