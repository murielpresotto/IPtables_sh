#!/bin/bash
flags()
	for FLAGS in $(cat /etc/firewall/flags.txt | grep -v ^#)
	do
		for CHAINS in INPUT FORWARD
		do
			iptables -A $CHAINS -p tcp --tcp-flags $FLAGS $FLAGS -j LOG --log-prefix "flags_$FLAGS"
			iptables -A $CHAINS -p tcp --tcp-flags $FLAGS $FLAGS -j DROP
		done
	done
flags
