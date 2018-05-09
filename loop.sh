#!/bin/bash
loop()
	{
		iptables -A INPUT -i lo -d 127.0.0.1 -j ACCEPT
		iptables -A OUTPUT -o lo -d 127.0.0.1 -j ACCEPT
	}
loop
