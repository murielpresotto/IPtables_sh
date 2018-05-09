#!/bin/bash
#func_OPERACAO_FIREWALL(){
#	echo $0 $1 "Executado em $(date +%d-%m-%Y-%H:%M:%S)" 2>&1 >> /var/log/firewall.log
#}
#func_OPERACAO_FIREWALL
echo $0 $1 "Executado em $(date +%d-%m-%Y-%H:%M:%S)" >> /var/log/firewall.log
cat /var/log/firewall.log
