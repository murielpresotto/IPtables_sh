#!/bin/bash
mac_ssh()
	{
		iptables -A INPUT -p tcp -s 10.11.1.55 --sport 1024:65535 -d 10.11.1.185 --dport 22 -m mac --mac-source 34:36:d7:5f:22:14 -j ACCEPT
		iptables -A OUTPUT -p tcp -s 10.11.1.185 --sport 22 -d 10.11.1.55 --dport 1024:65535 -j ACCEPT
	}
mac_ssh

