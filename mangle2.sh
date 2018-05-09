#!/bin/bash

#INterfaces ADSL

#Gateway das ADSLs

#limpa tabelas de roteamento no cache
ip route flush cache

#definicao da tabela dinamica a partir das marcas
ip rule add fwmark 10 table link1 prio 20
ip rule add fwmark 20 table link2 prio 20

#definicao de rotas para pacotes marcados
ip route add default via 10.0.2.2 table link1
ip route add default via 10.0.4.2 table link2

#adicione rota principal na tabela link1
ip route show table main | grep -Ev '^default' | while read ROUTE ; do ip route add table link1 $ROUTE; done

#escreve o fwmark da tabela a partir do estado do pacote
iptables -t mangle -A PREROUTING -j CONNMARK --restore-mark

#aceita apenas pacotes que nao possuam a marca 0
iptables -t mangle -A PREROUTING -m mark ! --mark 0 -j ACCEPT

#escreve o fwmark 10 (link1) em um pacote IP
iptables -t mangle -A PREROUTING -j MARK --set-mark 10

#seleciona 50% dos pacotes aleatorios para o fwmark 20 (link2)
iptables -t mangle -A PREROUTING -m statistic --mode random --probability 0.5 -j MARK --set-mark 20

#escreve o fwmark do pacote a partir do estado da tabela
iptables -t mangle -A PREROUTING -j CONNMARK --save-mark

#Mascara as saidas para os dois ADSLs
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth2 -j MASQUERADE
