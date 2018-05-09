#!/bin/bash
mac_nat()
	{
		iptables -I FORWARD -s 192.168.200.2 -m mac --mac-source 08:00:27:3f:03:bc -j DROP
	}
mac_nat
