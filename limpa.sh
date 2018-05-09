#!/bin/bash
limpa()
	{
		iptables -F
		iptables -F -t nat
		iptables -F -t mangle
		iptables -P INPUT ACCEPT
		iptables -P OUTPUT ACCEPT
		iptables -P FORWARD ACCEPT
	}
limpa
