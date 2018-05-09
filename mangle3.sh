#!/bin/bash
### Mascarar saídas para os dois ADSLs
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -t nat -A POSTROUTING -o eth2 -j MASQUERADE
# ## Marcar entrada de pacotes WEB e FTP
iptables -t mangle -A PREROUTING -i eth1 -p tcp --dport 80 -j MARK --set-mark 10
iptables -t mangle -A PREROUTING -i eth1 -p tcp --dport 443 -j MARK --set-mark 20
# ## Marcar saída de pacotes WEB e FTP
iptables -t mangle -A OUTPUT -p tcp --dport 80 -j MARK --set-mark 10
iptables -t mangle -A OUTPUT -p tcp --dport 22 -j MARK --set-mark 20
# ## Limpa tabelas de roteamento no cache
ip route flush cache
# ## Definição da tabelas dinâmicas a partir das marcas
ip rule add fwmark 10 table link1 prio 20
ip rule add fwmark 20 table link2 prio 20
# ## Definição de rotas para pacotes marcados
ip route add default via 10.0.2.2 dev eth0 table link1
ip route add default via 10.0.4.2 dev eth2 table link2
