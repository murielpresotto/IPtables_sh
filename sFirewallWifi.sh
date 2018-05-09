#!/bin/bash

  #################################################################
  ## Variaveis                                                        
  #################################################################

  # Comandos
  v_CMD_IPTABLES=$(which iptables) # caminho do executavel do comando iptables
  v_CMD_MODPROBE=$(which modprobe) # caminho do executavel do comamdo modprobe

  # REDES
  v_ALL_NETS='0/0'

  # VLANS
  v_VLAN_FAA_WIFI='192.168.213.0/24'
  
  # INTERFACES
  v_ETH_INTERFACE_PPP='pppx'
  v_ETH_INTERFACE_NET='eth0'
  v_ETH_INTERFACE_ODO='eth1'

  # IPS INTERFACES
  v_IP_INTERFACE_NET='192.168.213.254'
  v_IP_INTERFACE_ADM='192.168.213.1'

  # PORTAS
  v_PORTAS_ALTAS="1024:65535"
  v_PORTA_PROXY="4128"
  v_PORTA_DNS="53"
  v_PORTAS_EMAIL="995,993,143,110,465,587,25"
  v_PORTAS_SAMBA_UDP="137,138"
  v_PORTAS_SAMBA_TCP="139,445"

########################################
# INICIO DA CRIAÇÃO DAS REGRAS         #
########################################

# ATIVANDO O COMPARTILHAMENTO ENTRE PLACAS
func_ENABLE_IPFORWARD(){
  ip_forward=`cat /proc/sys/net/ipv4/ip_forward`
  if [ $ip_forward -eq 0 ];
    then 
    echo "1" > /proc/sys/net/ipv4/ip_forward
  fi
}

func_MODULOS(){
  $v_CMD_MODPROBE ip_conntrack_ftp
  $v_CMD_MODPROBE iptable_nat
  $v_CMD_MODPROBE ip_nat_ftp
  $v_CMD_MODPROBE ipt_MASQUERADE
}

func_LIMPANDO_REGRAS(){
  $v_CMD_IPTABLES -F
  $v_CMD_IPTABLES -t nat -F
  $v_CMD_IPTABLES -F INPUT
  $v_CMD_IPTABLES -F OUTPUT
  $v_CMD_IPTABLES -F FORWARD
  $v_CMD_IPTABLES -Z 
  $v_CMD_IPTABLES -t nat -F PREROUTING
  $v_CMD_IPTABLES -t nat -F OUTPUT
  $v_CMD_IPTABLES -t nat -F POSTROUTING
  $v_CMD_IPTABLES -Z -t nat
}

func_POLITICA_ACCEPT(){
  $v_CMD_IPTABLES -P INPUT ACCEPT
  $v_CMD_IPTABLES -P FORWARD ACCEPT 
  $v_CMD_IPTABLES -P OUTPUT ACCEPT 
  $v_CMD_IPTABLES -A OUTPUT -d 127.0.0.1 -j ACCEPT
  $v_CMD_IPTABLES -A INPUT -d 127.0.0.1 -j ACCEPT
}

func_POLITICA_DROP(){
  $v_CMD_IPTABLES -P INPUT DROP
  $v_CMD_IPTABLES -P FORWARD DROP 
  $v_CMD_IPTABLES -P OUTPUT ACCEPT 
  $v_CMD_IPTABLES -A OUTPUT -s 127.0.0.1 -j ACCEPT
  $v_CMD_IPTABLES -A INPUT -d 127.0.0.1 -j ACCEPT
}

func_ATIVA_LOG(){
  $v_CMD_IPTABLES -I INPUT -j LOG --log-level 6 --log-prefix "<<fw-INPUT>>: "
  $v_CMD_IPTABLES -I OUTPUT -j LOG --log-level 6 --log-prefix "<<fw-OUTPUT>>: "
  $v_CMD_IPTABLES -I FORWARD -j LOG --log-level 6 --log-prefix "<<fw-FORWARD>>: "
  $v_CMD_IPTABLES -t nat -I PREROUTING -j LOG --log-level 6 --log-prefix "<<fw-PREROUTING>>: "
  $v_CMD_IPTABLES -t nat -I POSTROUTING -j LOG --log-level 6 --log-prefix "<<fw-POSTROUTING>>: "
}

func_DESATIVA_LOG(){
  $v_CMD_IPTABLES -D INPUT -j LOG --log-level 6 --log-prefix "<<fw-INPUT>>: "
  $v_CMD_IPTABLES -D OUTPUT -j LOG --log-level 6 --log-prefix "<<fw-OUTPUT>>: "
  $v_CMD_IPTABLES -D FORWARD -j LOG --log-level 6 --log-prefix "<<fw-FORWARD>>: "
  $v_CMD_IPTABLES -D nat -I PREROUTING -j LOG --log-level 6 --log-prefix "<<fw-PREROUTING>>: "
  $v_CMD_IPTABLES -D nat -I POSTROUTING -j LOG --log-level 6 --log-prefix "<<fw-POSTROUTING>>: "
}

#################################################################
# [EXECEPION]
#################################################################

func_HOST(){
  echo "Regras host"
  $v_CMD_IPTABLES -A OUTPUT -p udp -s $v_IP_INTERFACE_NET --sport $v_PORTAS_ALTAS -d $v_ALL_NETS --dport $v_PORTA_DNS -j ACCEPT
  $v_CMD_IPTABLES -A INPUT -p udp -d $v_IP_INTERFACE_NET --dport $v_PORTAS_ALTAS -s $v_ALL_NETS --sport $v_PORTA_DNS -j ACCEPT

  $v_CMD_IPTABLES -A OUTPUT -p tcp -s $v_IP_INTERFACE_NET --sport $v_PORTAS_ALTAS -d $v_ALL_NETS --dport 80 -j ACCEPT
  $v_CMD_IPTABLES -A INPUT -p tcp -d $v_IP_INTERFACE_NET --dport $v_PORTAS_ALTAS -s $v_ALL_NETS --sport 80 -j ACCEPT

  $v_CMD_IPTABLES -A OUTPUT -p tcp -s $v_IP_INTERFACE_NET --sport $v_PORTAS_ALTAS -d $v_ALL_NETS --dport 443 -j ACCEPT
  $v_CMD_IPTABLES -A INPUT -p tcp -d $v_IP_INTERFACE_NET --dport $v_PORTAS_ALTAS -s $v_ALL_NETS --sport 443 -j ACCEPT

  $v_CMD_IPTABLES -A OUTPUT -p tcp -s $v_ALL_NETS --sport $v_PORTAS_ALTAS -d $v_IP_FAA -j ACCEPT
  $v_CMD_IPTABLES -A INPUT -p tcp -d $v_ALL_NETS --dport $v_PORTAS_ALTAS -s $v_IP_FAA -j ACCEPT

  $v_CMD_IPTABLES -A INPUT -p icmp --icmp-type 11 -s $v_IP_INTERFACE_NET -j ACCEPT

  $v_CMD_IPTABLES -A INPUT -p tcp --syn --dport 42129 -j ACCEPT
}
#################################################################
# [EXECEPIONS] - VLAN ADM
#################################################################

func_REGRAS_GERAIS(){
  echo "Regras gerais"
  $v_CMD_IPTABLES -A INPUT -p tcp -s $v_VLAN_FAA_WIFI -d $v_ALL_NETS --dport 4128 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_WIFI -d $v_ALL_NETS --dport $v_PORTA_PROXY -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_WIFI -d $v_ALL_NETS --dport $v_PORTA_DNS -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_WIFI -d $v_ALL_NETS -m multiport --dport $v_PORTAS_EMAIL -j ACCEPT
}

func_COMPARTILHANDO_INTERNET(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_WIFI -o ppp0 -j MASQUERADE
}

func_ESTABILIZANDO_CONEXOES(){
  $v_CMD_IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  $v_CMD_IPTABLES -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
  $v_CMD_IPTABLES -t nat -A PREROUTING -m state --state ESTABLISHED,RELATED -j ACCEPT
  $v_CMD_IPTABLES -t nat -A POSTROUTING -m state --state ESTABLISHED,RELATED -j ACCEPT
}

func_ENABLE_IPFORWARD
func_MODULOS
func_LIMPANDO_REGRAS
func_POLITICA_DROP
func_HOST
func_REGRAS_GERAIS
func_COMPARTILHANDO_INTERNET
func_ESTABILIZANDO_CONEXOES


