#!/bin/bash
nega()
	{
		iptables -P INPUT DROP
		iptables -P OUTPUT DROP
		iptables -P FORWARD DROP
	}
nega
