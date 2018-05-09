#!/bin/bash

# Script de Firewall

# Desenvolvido por: MSc.Joatham Pedro
# youtube.com/qualteupapo
# 

# Iniciado em 04/05/2018
echo "Kali Linux 2.0";

# Ativa mensagens da tela
MODO_TAGARELA=FALSE;

###########################################################################################################################################
## Variáveis                                                         
###########################################################################################################################################

# Comandos
v_CMD_IPTABLES=$(which iptables)	# caminho do executável do comando iptables
v_CMD_MODPROBE=$(which modprobe)	# caminho do executável do comamdo modprobe
v_CMD_ROUTE=$(which route)		# caminho do executavel do comando route
v_CMD_SQUID=$(which squid3) 		# caminho do executavel do comando squid3

# paths
v_PATH='/etc/squid3/';
v_ARQUIVO='squid.conf'
v_SUFIXO_TMP='_tmp';
v_SUFIXO_OLD='_old';

v_DATA=$(date +%Y%m%d-%T) 

function func_DISABLE_ACL_SQUID(){
  cp $v_PATH$v_ARQUIVO $v_PATH$v_DATA.$v_ARQUIVO
  sed -e "s/http_access allow $1/#http_access allow $1/" $v_PATH$v_ARQUIVO >> $v_PATH$v_ARQUIVO$v_SUFIXO_TMP
  mv $v_PATH$v_ARQUIVO $v_PATH$v_ARQUIVO$v_SUFIXO_OLD
  mv $v_PATH$v_ARQUIVO$v_SUFIXO_TMP $v_PATH$v_ARQUIVO
  $v_CMD_SQUID -k reconfigure
  rm $v_PATH$v_ARQUIVO$v_SUFIXO_OLD
}
function func_ENABLE_ACL_SQUID(){
  cp $v_PATH$v_ARQUIVO $v_PATH$v_DATA.$v_ARQUIVO
  sed -e "s/#http_access allow $1/http_access allow $1/" $v_PATH$v_ARQUIVO >> $v_PATH$v_ARQUIVO$v_SUFIXO_TMP
  mv $v_PATH$v_ARQUIVO $v_PATH$v_ARQUIVO$v_SUFIXO_OLD
  mv $v_PATH$v_ARQUIVO$v_SUFIXO_TMP $v_PATH$v_ARQUIVO
  $v_CMD_SQUID -k reconfigure
  rm $v_PATH$v_ARQUIVO$v_SUFIXO_OLD
}

# Interfaces
v_ETH1_INTERFACE_NET='eth1'; 		# interface de rede responsável por receber link LinkX
v_ETH0_INTERFACE_ADM='eth0'; 		# interface de rede direcionada a rede administrativa
v_ETH2_INTERFACE_DMZ='eth2'; 		# interface de rede direcionada a rede academica
v_ETHP_INTERFACE_PPP='ppp0';		# interface de rede virtual - velox

# IP's de cada interface
v_IP_INTERFACE_NET='187.95.32.124';	# IP configurado na interface eth1 - IP LinkX
v_IP_INTERFACE_ADM='192.168.254.1';	# IP configurado na interface eth0 - IP Rede Administrativa
v_IP_INTERFACE_DMZ='192.168.254.17';	# IP configurado na interface eth2 - IP Rede DMZ

###########################################################################################################################################
# Redes
###########################################################################################################################################

v_ALL_NETWORKS="0/0"

###########################################################################################################################################
# IMPRESSORAS
###########################################################################################################################################

v_IP_IMPRESSORA_FAA_IMP01='192.168.254.11'	# Compras    - HP LaserJet 3052
v_IP_IMPRESSORA_FAA_IMP02='192.168.254.12' 	# Protocolo  - kyocera FS-3900DN
v_IP_IMPRESSORA_FAA_IMP03='192.168.254.13'	# Protocolo  - kyocera KM-2050
v_IP_IMPRESSORA_FAA_IMP03='192.168.254.14'	# Secretaria - kyocera KM-2820

###########################################################################################################################################
# SERVIDORES
###########################################################################################################################################

# SLPACAD :
# S: Server H: host
# R: real V: Virtual
# L: Linux : W: Windows
# P: Producao T: Test B: Backup
# ACAD: Academico

v_VLAN_FAA_ADM_GTI='192.168.254.0/28';		# SubRede Servidores Firewall

v_IP_SERVIDOR_FAA_ADM_GATEWAY='192.168.254.1';

v_VLAN_FAA_ADM_DMZ='192.168.254.16/28';		# SubRede Servidores

v_IP_SERVIDOR_FAA_DMZ_GATEWAY='192.168.254.17';

v_IP_SERVIDOR_FAA_INTRA='192.168.254.18';	# INTRANET ( APLICATIVOS )
v_IP_SERVIDOR_FAA_DADOS='192.168.254.19';	# BANCO DE DADOS | APLICATIVO JACAD
v_IP_SERVIDOR_FAA_PROSO='192.168.254.20';	# PROSOFT
v_IP_SERVIDOR_FAA_VIRTU='192.168.254.21';	# AMBIENTE PARA VIRTUALIZAÇÃO
v_IP_SERVIDOR_FAA_JACAD='192.168.254.22';	# JACAD
v_IP_SERVIDOR_FAA_BNWEB='192.168.254.23';	# BIBLIOTECA ( VIRTUALIZADO )
v_IP_SERVIDOR_FAA_NAGIO='192.168.254.24';	# NAGIOS
v_IP_SERVIDOR_FAA_ADMIN='192.168.254.25';	# ADMINISTRATIVO
v_IP_SERVIDOR_FAA_ADNTI='192.168.254.26';	# FERRAMENTAS NTI ( GLPI | DOT PROJECT | OPENFIRE )
v_IP_SERVIDOR_FAA_ACADE='192.168.254.27';	# ACADEMICO
v_IP_SERVIDOR_FAA_BACKU='192.168.254.28';	# BACKUP
v_IP_SERVIDOR_FAA_AWIFI='192.168.254.29';	# WIFI

###########################################################################################################################################
# Portas
###########################################################################################################################################

# PORTAS sujeitas ao ataque de trojan
v_PORTAS_TROJANS="1234 1524 2583 3024 4092 5742 5556 5557 6000 6001 6002 6711 8787 12345 12346 16660 27444 27665 31335 31336 31337 31338 33270 60001 " 

v_PORTAS_ALTAS="1024:65535"
v_PORTAS_PSOFT="35000:35150"

v_PORTA_PROXY="4128"				# Porta usada pelo proxy

###########################################################################################################################################
#  Funcoes globais
###########################################################################################################################################

# a função devera solicitar um usuário, o mesmo deverá estar na lista de autorizados.
# ler de um arquivo externo (/etc/passwd)
func_VERIFICA_USER(){
  read user
  case $USER in
    root)
      logado=$(cut -f1 -d: /etc/passwd | grep $user)
      case $? in
        0)echo "OK !" ;;
        *)echo -e "\033[31m Operação não permitida, usuário não cadastrado *********** [FAIL] \033[m "; ;;
      esac
    ;;
    *)
      echo -e "\033[31m Operação permitida, você não é o administrador *********** [FAIL] \033[m ";
    ;;
  esac
}

status=3
func_STATUS(){
  case $status in
    1) echo -e "\033[34m Status do projeto - [ ANALISE ] **************** [OK] \033[m " ;;
    2) echo -e "\033[34m Status do projeto - [ DESENVOLVIMENTO ] ******** [OK] \033[m " ;;
    3) echo -e "\033[34m Status do projeto - [ TESTE ] ****************** [OK] \033[m " ;;
    4) echo -e "\033[34m Status do projeto - [ AJUSTES FINAIS ] ********* [OK] \033[m " ;;
    5) echo -e "\033[34m Status do projeto - [ PRODUÇÃO ] *************** [OK] \033[m " ;;
    *) echo -e "\033[31m SELECIONE UMA FASE - ************************* [FAIL] \033[m " ;;
  esac
} 

###########################################################################################################################################
#  Regras
###########################################################################################################################################

###########################################################################################################################################
# Habilita roteamento entre placas                            
###########################################################################################################################################

func_IP_FORWARD(){
  echo -e "\033[34m Habilitando roteamento entre as placas ********* [OK] \033[m ";

  ip_forward=`cat /proc/sys/net/ipv4/ip_forward`
  if [ $ip_forward -eq 0 ];
    then 
      echo "1" > /proc/sys/net/ipv4/ip_forward
  fi
}

func_MODPROBE(){
  echo -e "\033[34m Caregando módulos necessarios ****************** [OK] \033[m ";

  $v_CMD_MODPROBE iptable_nat
  $v_CMD_MODPROBE ip_conntrack_ftp
  $v_CMD_MODPROBE ip_nat_ftp
  $v_CMD_MODPROBE ip_conntrack
  $v_CMD_MODPROBE ip_conntrack_irc
  $v_CMD_MODPROBE ip_nat_irc
  $v_CMD_MODPROBE ipt_state
  $v_CMD_MODPROBE ip_tables
  $v_CMD_MODPROBE ipt_REDIRECT
  $v_CMD_MODPROBE ipt_LOG
  $v_CMD_MODPROBE ipt_REJECT
  $v_CMD_MODPROBE ipt_MASQUERADE
  $v_CMD_MODPROBE ipt_limit
}

func_CLEAR_RULES(){
  echo -e "\033[34m Limpando regras existentes ********************* [OK] \033[m ";

  $v_CMD_IPTABLES -F
  $v_CMD_IPTABLES -X
  $v_CMD_IPTABLES -t nat -F
  $v_CMD_IPTABLES -F INPUT
  $v_CMD_IPTABLES -F OUTPUT
  $v_CMD_IPTABLES -F FORWARD
  $v_CMD_IPTABLES -Z 
  $v_CMD_IPTABLES -t nat -F PREROUTING
  $v_CMD_IPTABLES -t nat -F OUTPUT
  $v_CMD_IPTABLES -t nat -F POSTROUTING
  $v_CMD_IPTABLES -Z -t nat
  $v_CMD_IPTABLES -t mangle -F PREROUTING
  $v_CMD_IPTABLES -t mangle -F OUTPUT
  $v_CMD_IPTABLES -t mangle -F POSTROUTING
  $v_CMD_IPTABLES -Z -t mangle
}

func_LOG_YES(){
  echo -e "\033[34m Ativando gravação de LOG *********************** [OK] \033[m ";

  $v_CMD_IPTABLES -I INPUT -j LOG --log-level 6 --log-prefix "<<CHAIN-INPUT>>: "
  $v_CMD_IPTABLES -I OUTPUT -j LOG --log-level 6 --log-prefix "<<CHAIN-OUTPUT>>: "
  $v_CMD_IPTABLES -I FORWARD -j LOG --log-level 6 --log-prefix "<<CHAIN-FORWARD>>: "
  $v_CMD_IPTABLES -t nat -I PREROUTING -j LOG --log-level 6 --log-prefix "<<CHAIN-PREROUTING>>: "
  $v_CMD_IPTABLES -t nat -I POSTROUTING -j LOG --log-level 6 --log-prefix "<<CHAIN-POSTROUTING>>: "
}

func_LOG_NO(){
  echo -e "\033[31m Desativando gravação de LOG ******************** [OK] \033[m ";
  $v_CMD_IPTABLES -D INPUT -j LOG --log-level 6 --log-prefix "<<CHAIN-INPUT>>: "
  $v_CMD_IPTABLES -D OUTPUT -j LOG --log-level 6 --log-prefix "<<CHAIN-OUTPUT>>: "
  $v_CMD_IPTABLES -D FORWARD -j LOG --log-level 6 --log-prefix "<<CHAIN-FORWARD>>: "
  $v_CMD_IPTABLES -t nat -D PREROUTING -j LOG --log-level 6 --log-prefix "<<CHAIN-PREROUTING>>: "
  $v_CMD_IPTABLES -t nat -D POSTROUTING -j LOG --log-level 6 --log-prefix "<<CHAIN-POSTROUTING>>: "
}

func_POLICY_ACCEPT(){
 echo -e "\033[34m criando uma politica padrão ACCEPT ************* [OK] \033[m ";
 # Tabela Filter
 $v_CMD_IPTABLES -P INPUT ACCEPT 
 $v_CMD_IPTABLES -P FORWARD ACCEPT 
 $v_CMD_IPTABLES -P OUTPUT ACCEPT 
 $v_CMD_IPTABLES -A OUTPUT -d 127.0.0.1 -j ACCEPT
 $v_CMD_IPTABLES -A INPUT -d 127.0.0.1 -j ACCEPT
}

func_POLICY_DROP(){ 
 echo -e "\033[34m criando uma politica padrão DROP *************** [OK] \033[m ";
 #Tabela Filter
 $v_CMD_IPTABLES -P INPUT DROP
 $v_CMD_IPTABLES -P FORWARD DROP
 $v_CMD_IPTABLES -P OUTPUT ACCEPT 
 $v_CMD_IPTABLES -A OUTPUT -d 127.0.0.1 -j ACCEPT
 $v_CMD_IPTABLES -A INPUT -d 127.0.0.1 -j ACCEPT
}

###########################################################################################################################################
# Estabilizando as conexões | TEM QUE FINAL NO FINAL DO SCRIPT
###########################################################################################################################################

func_ESTABILIZA_INPUT(){
  echo -e "\033[34m Estabilizando conexões de INPUT **************** [OK] \033[m ";
  $v_CMD_IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
}

func_INVALID_INPUT_DROP(){
  echo -e "\033[31m Eliminando conexões invalidas da CHAIN INPUT  ** [OK] \033[m ";
  $v_CMD_IPTABLES -A INPUT -m state --state INVALID -j LOG --log-level 6 --log-prefix "<<CHAIN-INPUT-INVALID>>: "
  $v_CMD_IPTABLES -A INPUT -m state --state INVALID -j DROP
}

func_ESTABILIZA_OUTPUT(){
  echo -e "\033[34m Estabilizando conexões de OUTPUT *************** [OK] \033[m ";
  $v_CMD_IPTABLES -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
}

func_ESTABILIZA_FORWARrsssD(){
  echo -e "\033[34m Estabilizando conexões de FORWARD ************** [OK] \033[m ";
  $v_CMD_IPTABLES -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
}

func_ESTABILIZA_NAT_PREROUTING(){
  echo -e "\033[34m Estabilizando conexões da nat PREROUTING ******* [OK] \033[m ";
  $v_CMD_IPTABLES -t nat -A PREROUTING -m state --state ESTABLISHED,RELATED -j ACCEPT
  $v_CMD_IPTABLES -t nat -A POSTROUTING -m state --state ESTABLISHED,RELATED -j ACCEPT
}

###########################################################################################################################################
# Redirecionamentos 
###########################################################################################################################################

# Adiciona redirecionamento para suporte remoto ao servidor prosoft
func_ADICIONA_REDIRECIONAMENTO_TS_PROSOFT(){
  echo -e "\033[34m Adiciona DNAT TS - INTERNET -> GTI.FAA.PROSOFT ******************* [OK] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p tcp -s $v_ALL_NETWORKS -d $v_IP_INTERFACE_NET --dport 33306 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -d $v_IP_SERVIDOR_FAA_PROSO --dport 3389 -j ACCEPT
  $v_CMD_IPTABLES -t nat -A PREROUTING -d $v_IP_INTERFACE_NET -p tcp --dport 33306 -j DNAT --to-destination $v_IP_SERVIDOR_FAA_PROSO:3389
  $v_CMD_IPTABLES -t nat -A POSTROUTING -d $v_IP_SERVIDOR_FAA_PROSO -j SNAT --to $v_IP_SERVIDOR_FAA_ADM_GATEWAY
}

func_REMOVE_REDIRECIONAMENTO_TS_PROSOFT(){
  echo -e "\033[31m Remove DNAT TS - INTERNET -> GTI.FAA.PROSOFT ********************* [OK] \033[m ";
  $v_CMD_IPTABLES -D INPUT -p tcp -s $v_ALL_NETWORKS -d $v_IP_INTERFACE_NET --dport 33306 -j ACCEPT
  $v_CMD_IPTABLES -D FORWARD -p tcp -d $v_IP_SERVIDOR_FAA_PROSO --dport 3389 -j ACCEPT
  $v_CMD_IPTABLES -t nat -D PREROUTING -d $v_IP_INTERFACE_NET -p tcp --dport 33306 -j DNAT --to-destination $v_IP_SERVIDOR_FAA_PROSO:3389
  $v_CMD_IPTABLES -t nat -D POSTROUTING -d $v_IP_SERVIDOR_FAA_PROSO -j SNAT --to $v_IP_SERVIDOR_FAA_ADM_GATEWAY
}

# Adiciona redirecionamento para acesso remota ao host nti03 - máquina do usuário Fernando Teixeira
func_REDIRECIONA_TS_NTI_03(){
  echo -e "\033[34m Adiciona DNAT TS - INTERNET -> IP_HOST_NTI_03 ******************** [OK] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p tcp -s $v_ALL_NETWORKS -d $v_IP_INTERFACE_NET --dport 43303 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -d $v_IP_HOST_NTI_03 --dport 3389 -j ACCEPT
  $v_CMD_IPTABLES -t nat -A PREROUTING -d $v_IP_INTERFACE_NET -p tcp --dport 43303 -j DNAT --to-destination $v_IP_HOST_NTI_03:3389
}

# Adiciona redirecionamento para acesso remota ao host cm01 - máquina do usuário Flavio Garcia
func_REDIRECIONA_TS_CM(){
  echo -e "\033[34m Adiciona DNAT TS - INTERNET -> IP_FAA_ADM_CTRLMENSALIDADE_H01 ***** [OK] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p tcp -s $v_ALL_NETWORKS -d $v_IP_INTERFACE_NET --dport 43305 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -d $v_IP_FAA_ADM_CTRLMENSALIDADE_H01 --dport 3389 -j ACCEPT
  $v_CMD_IPTABLES -t nat -A PREROUTING -d $v_IP_INTERFACE_NET -p tcp --dport 43305 -j DNAT --to-destination $v_IP_FAA_ADM_CTRLMENSALIDADE_H01:3389
}

# Adiciona redirecionamento para acesso ao servidor 10.10.10.2
func_REDIRECIONA_TS_WEBSERVER(){
  echo -e "\033[34m Adiciona DNAT TS - INTERNET -> IP_SERVIDOR_FAA_SVWPSSEC *********** [OK] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p tcp -s $v_ALL_NETWORKS -d $v_IP_INTERFACE_NET --dport 43389 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -d $v_IP_SERVIDOR_FAA_DADOS_OLD --dport 3389 -j ACCEPT
  $v_CMD_IPTABLES -t nat -A PREROUTING -d $v_IP_INTERFACE_NET -p tcp --dport 43389 -j DNAT --to-destination $v_IP_SERVIDOR_FAA_DADOS_OLD:3389
}

# Redirecionamento para suporte ao servidor da biblioteca
func_REDIRECIONA_TS_SISBIBLIOWEB(){
  echo -e "\033[34m Adiciona DNAT TS - INTERNET -> IP_SERVIDOR_FAA_SVWPBWEB *********** [OK] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p tcp -s $v_ALL_NETWORKS -d $v_IP_SERVIDOR_FAA_SVWPBWEB --dport 43319 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -d $v_IP_SERVIDOR_FAA_SVWPBWEB --dport 3389 -j ACCEPT
  $v_CMD_IPTABLES -t nat -A PREROUTING -d $v_IP_INTERFACE_NET -p tcp --dport 43319 -j DNAT --to-destination $v_IP_SERVIDOR_FAA_SVWPBWEB:3389
}

# Libera acesso para usuários externos ao spark
func_REDIRECIONA_OPENFIRE(){
  echo -e "\033[34m Adiciona DNAT OPENFIRE - INTERNET -> IP_SERVIDOR_FAA_SRLPADMI ****** [OK] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p tcp -s $v_ALL_NETWORKS -d $v_IP_INTERFACE_NET --dport 5222 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT
  $v_CMD_IPTABLES -t nat -A PREROUTING -d $v_IP_INTERFACE_NET -p tcp --dport 5222 -j DNAT --to-destination $v_IP_SERVIDOR_FAA_INTRA:5222
  $v_CMD_IPTABLES -t nat -A POSTROUTING -d $v_IP_SERVIDOR_FAA_INTRA -j SNAT --to $v_IP_SERVIDOR_FAA_ADM_GATEWAY
}

# libera acesso externo ao glpi
func_REDIRECIONA_GLPI(){
  echo -e "\033[34m Adiciona DNAT GLPI - INTERNET -> IP_SERVIDOR_FAA_SRLPADMI ********** [OK] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p tcp -s $v_ALL_NETWORKS -d $v_IP_INTERFACE_NET --dport 41180 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT
  $v_CMD_IPTABLES -t nat -A PREROUTING -d $v_IP_INTERFACE_NET -p tcp --dport 41180 -j DNAT --to-destination $v_IP_SERVIDOR_FAA_INTRA:80
  $v_CMD_IPTABLES -t nat -A POSTROUTING -d $v_IP_SERVIDOR_FAA_INTRA -j SNAT --to $v_IP_SERVIDOR_FAA_ADM_GATEWAY
}

# Libera acesso externo a administraçao do openfire
func_REDIRECIONA_ADM_OPENFIRE(){
  echo -e "\033[34m Adiciona DNAT OPENFIRE ADM - INTERNET -> IP_SERVIDOR_FAA_SRLPADMI ** [OK] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p tcp -s $v_ALL_NETWORKS -d $v_IP_INTERFACE_NET --dport 9090 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -d $v_IP_SERVIDOR_FAA_INTRA --dport 9090 -j ACCEPT
  $v_CMD_IPTABLES -t nat -A PREROUTING -d $v_IP_INTERFACE_NET -p tcp --dport 9090 -j DNAT --to-destination $v_IP_SERVIDOR_FAA_INTRA:9090
  $v_CMD_IPTABLES -t nat -A POSTROUTING -d $v_IP_SERVIDOR_FAA_INTRA -j SNAT --to $v_IP_SERVIDOR_FAA_ADM_GATEWAY
}

# Libera acesso externo ao bnweb
func_REDIRECIONA_BIBLIOTECA(){
  echo -e "\033[34m Adiciona DNAT WEB - INTERNET -> IP_SERVIDOR_FAA_SVWPBWEB *********** [OK] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p tcp -s $v_ALL_NETWORKS -d $v_IP_INTERFACE_NET --dport 41080 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -d 10.10.232.20 --dport 80 -j ACCEPT
  $v_CMD_IPTABLES -t nat -A PREROUTING -d $v_IP_INTERFACE_NET -p tcp --dport 41080 -j DNAT --to-destination 10.10.232.20:80
  $v_CMD_IPTABLES -t nat -A POSTROUTING -d 10.10.232.20 -j SNAT --to $v_IP_SERVIDOR_FAA_ADM_GATEWAY
}

func_REDIRECIONA_BIBLIOTECA_INTERNA(){
  echo -e "\033[34m Adiciona DNAT TS - INTERNET -> IP_SERVIDOR_FAA_SVWPBWEB ************ [OK] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p tcp -s $v_ALL_NETWORKS -d $v_IP_INTERFACE_NET --dport 41088 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -d 10.10.232.20 --dport 3389 -j ACCEPT
  $v_CMD_IPTABLES -t nat -A PREROUTING -d $v_IP_INTERFACE_NET -p tcp --dport 41088 -j DNAT --to-destination 10.10.232.20:3389
  $v_CMD_IPTABLES -t nat -A POSTROUTING -d 10.10.232.20 -j SNAT --to $v_IP_SERVIDOR_FAA_ADM_GATEWAY
}

###########################################################################################################################################
# Controle de pacotes icmp
###########################################################################################################################################

func_DROP_PING_EXTERNO(){
  echo -e "\033[34m Controle de pacotes icmp externos ************** [OK] \033[m ";
  $v_CMD_IPTABLES -A FORWARD -p icmp --icmp-type ping -s $v_VLAN_FAA_ADM -i eth0 -d 0/0 -o eth1 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p icmp --icmp-type pong -s 0/0 -i eth1 -d $v_VLAN_FAA_ADM -o eth0 -j ACCEPT
}

func_LIMITA_PING_ADM(){
  echo -e "\033[34m Controle de pacotes icmp internos ************** [OK] \033[m ";
  $v_CMD_IPTABLES -A OUTPUT -p icmp --icmp-type 0 -s $v_VLAN_FAA_ADM -m limit --limit 1/s -j ACCEPT
  $v_CMD_IPTABLES -A OUTPUT -p icmp --icmp-type 8 -s $v_VLAN_FAA_ADM -m limit --limit 1/s -j ACCEPT
  $v_CMD_IPTABLES -A INPUT -p icmp --icmp-type 0 -s $v_VLAN_FAA_ADM -m limit --limit 1/s -j ACCEPT
  $v_CMD_IPTABLES -A INPUT -p icmp --icmp-type 8 -s $v_VLAN_FAA_ADM -m limit --limit 1/s -j ACCEPT
}

###########################################################################################################################################
# Controle - portscanner
###########################################################################################################################################

func_BLOQUEIO_NMAP(){
  echo -e "\033[34m Controle de pacotes tcp - nmap - bloqueio  ***** [ok] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p tcp --tcp-flags SYN, ACK -m limit --limit 5/s -j REJECT
  $v_CMD_IPTABLES -A INPUT -p tcp --tcp-flags SYN, RST -m limit --limit 5/s -j REJECT
}

func_BLOQUEIO_PORTSCANNER(){
  echo -e "\033[34m Controle de pacotes tcp - portScanner - bloqueio [ok] \033[m ";
  $v_CMD_IPTABLES -N SCANNER
  $v_CMD_IPTABLES -A SCANNER -m limit --limit 15/m -j LOG --log-level 6 --log-prefix "FIREWALL:port-scanner:"
  $v_CMD_IPTABLES -A SCANNER -j REJECT

  $v_CMD_IPTABLES -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -i $v_ETH1_INTERFACE_NET -j SCANNER
  $v_CMD_IPTABLES -A INPUT -p tcp --tcp-flags ALL NONE -i $v_ETH1_INTERFACE_NET -j SCANNER
  $v_CMD_IPTABLES -A INPUT -p tcp --tcp-flags ALL ALL -i $v_ETH1_INTERFACE_NET -j SCANNER
  $v_CMD_IPTABLES -A INPUT -p tcp --tcp-flags ALL FIN,SYN -i $v_ETH1_INTERFACE_NET -j SCANNER
  $v_CMD_IPTABLES -A INPUT -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -i $v_ETH1_INTERFACE_NET -j SCANNER
  $v_CMD_IPTABLES -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -i $v_ETH1_INTERFACE_NET -j SCANNER
  $v_CMD_IPTABLES -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -i $v_ETH1_INTERFACE_NET -j SCANNER
}

###########################################################################################################################################
# Controle - worm
###########################################################################################################################################

func_BLOQUEIO_WORN_TCP(){
  echo -e "\033[34m Controle de pacotes tcp - worm - bloqueio  ***** [ok] \033[m ";
  $v_CMD_IPTABLES -N WORMS_TCP
  $v_CMD_IPTABLES -A WORMS_TCP -m limit --limit 15/m -j LOG --log-level 6 --log-prefix "FIREWALL:worm-por-tcp:"
  $v_CMD_IPTABLES -A WORMS_TCP -j REJECT
}

func_BLOQUEIO_WORN_UDP(){
  echo -e "\033[34m Controle de pacotes udp - worm - bloqueio  ***** [ok] \033[m ";
  # WORMS POR PORTAS UDP
  $v_CMD_IPTABLES -N WORMS_UDP
  $v_CMD_IPTABLES -A WORMS_UDP -m limit --limit 15/m -j LOG --log-level 6 --log-prefix "FIREWALL:worm-por-udp:"
  $v_CMD_IPTABLES -A WORMS_UDP -j REJECT
}

func_BLOQUEIO_DOS_TRIN00(){
  echo -e "\033[34m Controle de pacotes udp - TRIN00 - bloqueio **** [ok] \033[m ";
  $v_CMD_IPTABLES -N TRINOO
  $v_CMD_IPTABLES -A TRINOO -m limit --limit 15/m -j LOG --log-level 6 --log-prefix "FIREWALL:trinoo:"
  $v_CMD_IPTABLES -A TRINOO -j REJECT
  $v_CMD_IPTABLES -A INPUT -p TCP -i $v_ETH1_INTERFACE_NET --dport 27444 -j TRINOO
  $v_CMD_IPTABLES -A INPUT -p TCP -i $v_ETH1_INTERFACE_NET --dport 27665 -j TRINOO
  $v_CMD_IPTABLES -A INPUT -p TCP -i $v_ETH1_INTERFACE_NET --dport 31335 -j TRINOO
  $v_CMD_IPTABLES -A INPUT -p TCP -i $v_ETH1_INTERFACE_NET --dport 34555 -j TRINOO
  $v_CMD_IPTABLES -A INPUT -p TCP -i $v_ETH1_INTERFACE_NET --dport 35555 -j TRINOO 
}

func_BLOQUEIO_PORTAS_TROJAN(){
  echo -e "\033[34m Controle de pacotes udp/tcp - trojan - bloqueio *[ok] \033[m ";
  $v_CMD_IPTABLES -t filter -N portsTrojan-in

  for PORTA in ${v_PORTAS_TROJANS};do
    $v_CMD_IPTABLES -A portsTrojan-in -p tcp --sport 1024: --dport ${PORTA} -j LOG --log-prefix "FIREWALL:Trojan tcp p:${PORTA}"
    $v_CMD_IPTABLES -A portsTrojan-in -p tcp --sport 1024: --dport ${PORTA} -j REJECT
    $v_CMD_IPTABLES -A portsTrojan-in -p udp --sport 1024: --dport ${PORTA} -j LOG --log-prefix "FIREWALL:Trojan udp p:${PORTA}"
    $v_CMD_IPTABLES -A portsTrojan-in -p udp --sport 1024: --dport ${PORTA} -j REJECT  
  done
  $v_CMD_IPTABLES -t filter -A INPUT -i $v_ETH1_INTERFACE_NET -j portsTrojan-in
}

###########################################################################################################################################
# Controle - Portas extras
###########################################################################################################################################

func_BLOQUEIO_PORTAS_EXTRAS_TCP(){
  echo -e "\033[34m Controle de PORTAS extras - bloqueio *********** [ok] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p tcp --dport 135 -i $v_ETH1_INTERFACE_NET -j REJECT
  $v_CMD_IPTABLES -A INPUT -p tcp --dport 111 -i $v_ETH1_INTERFACE_NET -j REJECT
  $v_CMD_IPTABLES -A INPUT -p tcp --dport 3000 -i $v_ETH1_INTERFACE_NET -j REJECT
}

func_BLOQUEIO_PORTAS_EXTRAS_UDP(){
  echo -e "\033[34m Controle de PORTAS extras - bloqueio *********** [ok] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p udp --dport 135 -i $v_ETH1_INTERFACE_NET -j REJECT
}

###########################################################################################################################################
# [EXECEPIONS] - SERVIDORES
###########################################################################################################################################
#192.168.254.16/28
v_VLAN_FAA_ADM_GTI='192.168.254.16/28';
v_VLAN_FAA_ADM_GTI_ROTA='-net 192.168.254.16 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_GTI(){
  route add $v_VLAN_FAA_ADM_GTI_ROTA gw $v_IP_SERVIDOR_FAA_DMZ_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_GTI ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_GTI(){
  route del $v_VLAN_FAA_ADM_GTI_ROTA gw $v_IP_SERVIDOR_FAA_DMZ_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_GTI *[OK] \033[m ";
}

func_ENABLE_NET_ADM_GTI(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_GTI -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_GTI(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_GTI -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_GTI_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_GTI -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_GTI_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_GTI -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_GTI(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_GTI -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_GTI -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT
}
###########################################################################################################################################
# [EXECEPIONS] - HOST FIREWALL
###########################################################################################################################################
func_HOST_FIREWALL_LIBERA_DNS(){
  echo -e "\033[34m EXCESSÕES HOST - LIBERA ACESSO A POSTAS DNS ************************ [OK] \033[m ";
  $v_CMD_IPTABLES -A OUTPUT -p udp -s $v_IP_INTERFACE_NET --sport $v_PORTAS_ALTAS -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A INPUT -p udp -d $v_IP_INTERFACE_NET --dport $v_PORTAS_ALTAS -s $v_ALL_NETWORKS --sport 53 -j ACCEPT
}

func_HOST_FIREWALL_LIBERA_WEB(){
  echo -e "\033[34m EXCESSÕES HOST - LIBERA ACESSO A POSTAS WEB ************************ [OK] \033[m ";
  $v_CMD_IPTABLES -A OUTPUT -p tcp -s $v_IP_INTERFACE_NET --sport $v_PORTAS_ALTAS -d $v_ALL_NETWORKS --dport 80 -j ACCEPT
  $v_CMD_IPTABLES -A INPUT -p tcp -d $v_IP_INTERFACE_NET --dport $v_PORTAS_ALTAS -s $v_ALL_NETWORKS --sport 80 -j ACCEPT

  echo -e "\033[34m EXCESSÕES HOST - LIBERA ACESSO A POSTAS DNS ************************ [OK] \033[m ";
  # acesso ao aplicativos para monitoramento
  $v_CMD_IPTABLES -A OUTPUT -p tcp -s $v_IP_SERVIDOR_FAA_ADM_GATEWAY --sport 80 -d 10.10.232.3 --dport $v_PORTAS_ALTAS -j ACCEPT
  $v_CMD_IPTABLES -A INPUT -p tcp -d $v_IP_SERVIDOR_FAA_ADM_GATEWAY --dport 80 -s 10.10.232.3 --sport $v_PORTAS_ALTAS -j ACCEPT

  echo -e "\033[34m EXCESSÕES HOST - LIBERA ACESSO A POSTAS DNS ************************ [OK] \033[m ";
  $v_CMD_IPTABLES -A OUTPUT -p tcp -s $v_IP_INTERFACE_NET --sport $v_PORTAS_ALTAS -d $v_ALL_NETWORKS --dport 443 -j ACCEPT
  $v_CMD_IPTABLES -A INPUT -p tcp -d $v_IP_INTERFACE_NET --dport $v_PORTAS_ALTAS -s $v_ALL_NETWORKS --sport 443 -j ACCEPT

  echo -e "\033[34m EXCESSÕES HOST - LIBERA ACESSO A POSTAS DNS ************************ [OK] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p tcp -i $v_ETH0_INTERFACE_ADM --dport $v_PORTA_PROXY -j ACCEPT
  $v_CMD_IPTABLES -A INPUT -p tcp -i $v_ETH0_INTERFACE_ADM --dport 41080 -j ACCEPT

  echo -e "\033[34m EXCESSÕES HOST - LIBERA ACESSO A POSTAS DNS ************************ [OK] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p tcp -i $v_ETH2_INTERFACE_DMZ --dport $v_PORTA_PROXY -j ACCEPT
  $v_CMD_IPTABLES -A INPUT -p tcp -i $v_ETH2_INTERFACE_DMZ --dport 41080 -j ACCEPT
}

func_HOST_FIREWALL_LIBERA_MTR(){
  echo -e "\033[34m EXCESSÕES HOST - LIBERA ACESSO A POSTAS DNS ************************ [OK] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p icmp --icmp-type 11 -s $v_IP_INTERFACE_NET -j ACCEPT
}

func_HOST_FIREWALL_LIBERA_SSH(){
  echo -e "\033[34m EXCESSÕES HOST - LIBERA ACESSO A POSTAS DNS ************************ [OK] \033[m ";
  $v_CMD_IPTABLES -A INPUT -p tcp --syn --dport 42129 -j ACCEPT
}

###########################################################################################################################################
# [EXECEPIONS] - VLAN NTI
###########################################################################################################################################
# NTI
#192.168.220.0/26
v_VLAN_FAA_ADM_NTI='192.168.220.0/26';
v_VLAN_FAA_ADM_NTI_ROTA='-net 192.168.220.0 netmask 255.255.255.192';

func_ADICIONA_TABELA_ROTAS_ADM_NTI(){
  route add $v_VLAN_FAA_ADM_NTI_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_NTI ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_NTI(){
  route del $v_VLAN_FAA_ADM_NTI_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_NTI *[OK] \033[m ";
}

func_ENABLE_NET_ADM_NTI(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_NTI -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_NTI(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_NTI -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_NTI_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_NTI -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_NTI_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_NTI -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_NTI(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_NTI -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_NTI -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_NTI -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_NTI -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_NTI -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_NTI -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_NTI -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_NTI -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_NTI -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_NTI -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_NTI -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################
# INICIO DA CRIAÇÃO DE REGRAS
###########################################################################################################################################

###########################################################################################################################################
# BLOCOS / SETORES / HOSTS (exceções)
###########################################################################################################################################

###########################################################################################################################################
# BLOCO A - 192.168.100
###########################################################################################################################################
# NPJ
#192.168.100.0/28
v_VLAN_FAA_BLOCOA_NPJ='192.168.100.0/28';
v_VLAN_FAA_BLOCOA_NPJ_ROTA='-net 192.168.100.0 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_BLOCOA_NPJ(){
  route add $v_VLAN_FAA_BLOCOA_NPJ_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_BLOCOA_NPJ ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_BLOCOA_NPJ(){
  route del $v_VLAN_FAA_BLOCOA_NPJ_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_BLOCOA_NPJ *[OK] \033[m ";
}

func_ENABLE_NET_BLOCOA_NPJ(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOA_NPJ -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_BLOCOA_NPJ(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOA_NPJ -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_BLOCOA_NPJ_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOA_NPJ -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_BLOCOA_NPJ_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOA_NPJ -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_BLOCOA_NPJ(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOA_NPJ -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_NPJ -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_NPJ -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOA_NPJ -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOA_NPJ -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_NPJ -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOA_NPJ -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOA_NPJ -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOA_NPJ -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_NPJ -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_NPJ -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################	
# SALA DE COORDENAÇÃO
#192.168.100.16/28
v_VLAN_FAA_BLOCOA_DIRETORES='192.168.100.16/28';		
v_VLAN_FAA_BLOCOA_DIRETORES_ROTA='-net 192.168.100.16 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_BLOCOA_DIRETORES(){
  route add $v_VLAN_FAA_BLOCOA_DIRETORES_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_BLOCOA_DIRETORES ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_BLOCOA_DIRETORES(){
  route del $v_VLAN_FAA_BLOCOA_DIRETORES_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_BLOCOA_DIRETORES *[OK] \033[m ";
}

func_ENABLE_NET_BLOCOA_DIRETORES(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOA_DIRETORES -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_BLOCOA_DIRETORES(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOA_DIRETORES -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_BLOCOA_DIRETORES_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOA_DIRETORES -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_BLOCOA_DIRETORES_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOA_DIRETORES -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_BLOCOA_DIRETORES(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOA_DIRETORES -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_DIRETORES -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_DIRETORES -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOA_DIRETORES -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOA_DIRETORES -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_DIRETORES -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOA_DIRETORES -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOA_DIRETORES -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOA_DIRETORES -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_DIRETORES -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_DIRETORES -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}
###########################################################################################################################################	
# SALA DOS PROFESSORES
#192.168.100.32/28
v_VLAN_FAA_BLOCOA_PROFESSORES='192.168.100.32/28';		
v_VLAN_FAA_BLOCOA_PROFESSORES_ROTA='-net 192.168.100.32 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_BLOCOA_PROFESSORES(){
  route add $v_VLAN_FAA_BLOCOA_PROFESSORES_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_BLOCOA_PROFESSORES ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_BLOCOA_PROFESSORES(){
  route del $v_VLAN_FAA_BLOCOA_PROFESSORES_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_BLOCOA_PROFESSORES *[OK] \033[m ";
}

func_ENABLE_NET_BLOCOA_PROFESSORES(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOA_PROFESSORES -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_BLOCOA_PROFESSORES(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOA_PROFESSORES -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_BLOCOA_PROFESSORES_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOA_PROFESSORES -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_BLOCOA_PROFESSORES_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOA_PROFESSORES -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_BLOCOA_PROFESSORES(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOA_PROFESSORES -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_PROFESSORES -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_PROFESSORES -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOA_PROFESSORES -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOA_PROFESSORES -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT
}

###########################################################################################################################################	
# SECRETARIA
#192.168.100.48/28
v_VLAN_FAA_BLOCOA_SECRETARIA='192.168.100.48/28';		
v_VLAN_FAA_BLOCOA_SECRETARIA_ROTA='-net 192.168.100.48 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_BLOCOA_SECRETARIA(){
  route add $v_VLAN_FAA_BLOCOA_SECRETARIA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_BLOCOA_SECRETARIA ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_BLOCOA_SECRETARIA(){
  route del $v_VLAN_FAA_BLOCOA_SECRETARIA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_BLOCOA_SECRETARIA *[OK] \033[m ";
}

func_ENABLE_NET_BLOCOA_SECRETARIA(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOA_SECRETARIA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_BLOCOA_SECRETARIA(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOA_SECRETARIA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_BLOCOA_SECRETARIA_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOA_SECRETARIA -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_BLOCOA_SECRETARIA_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOA_SECRETARIA -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_BLOCOA_SECRETARIA(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOA_SECRETARIA -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_SECRETARIA -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_SECRETARIA -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOA_SECRETARIA -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOA_SECRETARIA -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_SECRETARIA -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOA_SECRETARIA -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOA_SECRETARIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOA_SECRETARIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_SECRETARIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_SECRETARIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################	
# AUDIO VISUAL
#192.168.100.64/28
v_VLAN_FAA_BLOCOA_AVISUAL='192.168.100.64/28';		
v_VLAN_FAA_BLOCOA_AVISUAL_ROTA='-net 192.168.100.64 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_BLOCOA_AVISUAL(){
  route add $v_VLAN_FAA_BLOCOA_AVISUAL_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_BLOCOA_AVISUAL ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_BLOCOA_AVISUAL(){
  route del $v_VLAN_FAA_BLOCOA_AVISUAL_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_BLOCOA_AVISUAL *[OK] \033[m ";
}

func_ENABLE_NET_BLOCOA_AVISUAL(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOA_AVISUAL -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_BLOCOA_AVISUAL(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOA_AVISUAL -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_BLOCOA_AVISUAL_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOA_AVISUAL -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_BLOCOA_AVISUAL_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOA_AVISUAL -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_BLOCOA_AVISUAL(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOA_AVISUAL -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_AVISUAL -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_AVISUAL -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOA_AVISUAL -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOA_AVISUAL -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_AVISUAL -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOA_AVISUAL -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOA_AVISUAL -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOA_AVISUAL -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_AVISUAL -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOA_AVISUAL -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################
# BLOCO B - 192.168.101
###########################################################################################################################################
# 1 ANDAR
###########################################################################################################################################	
# SECRETARIA
#192.168.101.0/28
v_VLAN_FAA_BLOCOB_SECRETARIA='192.168.101.0/28';		
v_VLAN_FAA_BLOCOB_SECRETARIA_ROTA='-net 192.168.101.0 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_BLOCOB_SECRETARIA(){
  route add $v_VLAN_FAA_BLOCOB_SECRETARIA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_BLOCOB_SECRETARIA ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_BLOCOB_SECRETARIA(){
  route del $v_VLAN_FAA_BLOCOB_SECRETARIA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_BLOCOB_SECRETARIA *[OK] \033[m ";
}

func_ENABLE_NET_BLOCOB_SECRETARIA(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOB_SECRETARIA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_BLOCOB_SECRETARIA(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOB_SECRETARIA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_BLOCOB_SECRETARIA_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOB_SECRETARIA -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_BLOCOB_SECRETARIA_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOB_SECRETARIA -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_BLOCOB_SECRETARIA(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOB_SECRETARIA -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOB_SECRETARIA -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOB_SECRETARIA -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOB_SECRETARIA -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOB_SECRETARIA -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOB_SECRETARIA -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOB_SECRETARIA -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOB_SECRETARIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOB_SECRETARIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOB_SECRETARIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOB_SECRETARIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################		
# SALA DOS PROFESSORES
#192.168.101.16/28
v_VLAN_FAA_BLOCOB_PROFESSORES='192.168.101.16/28';		
v_VLAN_FAA_BLOCOB_PROFESSORES_ROTA='-net 192.168.101.16 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_BLOCOB_PROFESSORES(){
  route add $v_VLAN_FAA_BLOCOB_PROFESSORES_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_BLOCOB_PROFESSORES ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_BLOCOB_PROFESSORES(){
  route del $v_VLAN_FAA_BLOCOB_PROFESSORES_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_BLOCOB_PROFESSORES *[OK] \033[m ";
}

func_ENABLE_NET_BLOCOB_PROFESSORES(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOB_PROFESSORES -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_BLOCOB_PROFESSORES(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOB_PROFESSORES -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_BLOCOB_PROFESSORES_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOB_PROFESSORES -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_BLOCOB_PROFESSORES_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOB_PROFESSORES -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_BLOCOB_PROFESSORES(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOB_PROFESSORES -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOB_PROFESSORES -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOB_PROFESSORES -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOB_PROFESSORES -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOB_PROFESSORES -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT
}
###########################################################################################################################################		
# PATOLOGIA
#192.168.101.32/28
v_VLAN_FAA_BLOCOB_LABORATORIOS='192.168.101.32/28';		
v_VLAN_FAA_BLOCOB_LABORATORIOS_ROTA='-net 192.168.101.32 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_BLOCOB_LABORATORIOS(){
  route add $v_VLAN_FAA_BLOCOB_LABORATORIOS_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_BLOCOB_LABORATORIOS ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_BLOCOB_LABORATORIOS(){
  route del $v_VLAN_FAA_BLOCOB_LABORATORIOS_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_BLOCOB_LABORATORIOS *[OK] \033[m ";
}

func_ENABLE_NET_BLOCOB_LABORATORIOS(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOB_LABORATORIOS -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_BLOCOB_LABORATORIOS(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOB_LABORATORIOS -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_BLOCOB_LABORATORIOS_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOB_LABORATORIOS -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_BLOCOB_LABORATORIOS_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOB_LABORATORIOS -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_BLOCOB_LABORATORIOS(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOB_LABORATORIOS -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOB_LABORATORIOS -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOB_LABORATORIOS -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOB_LABORATORIOS -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOB_LABORATORIOS -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT
}
###########################################################################################################################################
# 2 ANDAR
###########################################################################################################################################	
# CLINICA ODONTOLOGIA
#192.168.101.64/28
v_VLAN_FAA_BLOCOB_CLINICA='192.168.101.64/28';		
v_VLAN_FAA_BLOCOB_CLINICA_ROTA='-net 192.168.101.64 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_BLOCOB_CLINICA(){
  route add $v_VLAN_FAA_BLOCOB_CLINICA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_BLOCOB_CLINICA ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_BLOCOB_CLINICA(){
  route del $v_VLAN_FAA_BLOCOB_CLINICA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_BLOCOB_CLINICA *[OK] \033[m ";
}

func_ENABLE_NET_BLOCOB_CLINICA(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOB_CLINICA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_BLOCOB_CLINICA(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOB_CLINICA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_BLOCOB_CLINICA_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOB_CLINICA -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_BLOCOB_CLINICA_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOB_CLINICA -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_BLOCOB_CLINICA(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOB_CLINICA -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOB_CLINICA -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOB_CLINICA -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOB_CLINICA -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOB_CLINICA -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT
}
###########################################################################################################################################
# 3 ANDAR
###########################################################################################################################################	
# COORDENACAO BIOMEDICO
#192.168.101.80/28
v_VLAN_FAA_BLOCOB_LABORATORIOS='192.168.101.80/28';		
v_VLAN_FAA_BLOCOB_LABORATORIOS_ROTA='-net 192.168.101.80 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_BLOCOB_LABORATORIOS(){
  route add $v_VLAN_FAA_BLOCOB_LABORATORIOS_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_BLOCOB_LABORATORIOS ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_BLOCOB_LABORATORIOS(){
  route del $v_VLAN_FAA_BLOCOB_LABORATORIOS_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_BLOCOB_LABORATORIOS *[OK] \033[m ";
}

func_ENABLE_NET_BLOCOB_COORDENACAO(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOB_COORDENACAO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_BLOCOB_COORDENACAO(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOB_COORDENACAO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_BLOCOB_COORDENACAO_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BLOCOB_COORDENACAO -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_BLOCOB_COORDENACAO_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BLOCOB_COORDENACAO -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_BLOCOB_COORDENACAO(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOB_COORDENACAO -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOB_COORDENACAO -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOB_COORDENACAO -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOB_COORDENACAO -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOB_COORDENACAO -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOB_COORDENACAO -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BLOCOB_COORDENACAO -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOB_COORDENACAO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BLOCOB_COORDENACAO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOB_COORDENACAO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BLOCOB_COORDENACAO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################
# BIBLIOTECA - 192.168.102
###########################################################################################################################################	
#192.168.102.0/28
v_VLAN_FAA_BIBLIOTECA_ADM='192.168.102.0/28';		
v_VLAN_FAA_BIBLIOTECA_ADM_ROTA='-net 192.168.105.0 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_BIBLIOTECA_ADM(){
  route add $v_VLAN_FAA_BIBLIOTECA_ADM_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_BIBLIOTECA_ADM ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_BIBLIOTECA_ADM(){
  route del $v_VLAN_FAA_BIBLIOTECA_ADM_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_BIBLIOTECA_ADM *[OK] \033[m ";
}

func_ENABLE_NET_BIBLIOTECA_ADM(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BIBLIOTECA_ADM -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_BIBLIOTECA_ADM(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BIBLIOTECA_ADM -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_BIBLIOTECA_ADM_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_BIBLIOTECA_ADM -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_BIBLIOTECA_ADM_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_BIBLIOTECA_ADM -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_BIBLIOTECA_ADM(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BIBLIOTECA_ADM -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BIBLIOTECA_ADM -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BIBLIOTECA_ADM -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BIBLIOTECA_ADM -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BIBLIOTECA_ADM -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BIBLIOTECA_ADM -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_BIBLIOTECA_ADM -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BIBLIOTECA_ADM -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_BIBLIOTECA_ADM -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BIBLIOTECA_ADM -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_BIBLIOTECA_ADM -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################
# ADIMINISTRATIVO - 192.168.103 ( ANDAR 01 -PARTE 01)
# ADIMINISTRATIVO - 192.168.106 ( ANDAR 01 -PARTE 02)
# ADIMINISTRATIVO - 192.168.104 ( ANDAR 02 )
# ADIMINISTRATIVO - 192.168.105 ( DIREÇÃO )
###########################################################################################################################################
# PRESICENCIA
#192.168.105.0/28
v_VLAN_FAA_ADM_PRESIDENCIA='192.168.105.0/28';		
v_VLAN_FAA_ADM_PRESIDENCIA_ROTA='-net 192.168.105.0 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_PRESIDENCIA(){
  route add $v_VLAN_FAA_ADM_PRESIDENCIA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_PRESIDENCIA ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_PRESIDENCIA(){
  route del $v_VLAN_FAA_ADM_PRESIDENCIA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_PRESIDENCIA *[OK] \033[m ";
}

func_ENABLE_NET_ADM_PRESIDENCIA(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_PRESIDENCIA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_PRESIDENCIA(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_PRESIDENCIA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_PRESIDENCIA_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_PRESIDENCIA -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_PRESIDENCIA_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_PRESIDENCIA -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_PRESIDENCIA(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_PRESIDENCIA -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_PRESIDENCIA -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_PRESIDENCIA -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_PRESIDENCIA -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_PRESIDENCIA -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_PRESIDENCIA -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_PRESIDENCIA -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_PRESIDENCIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_PRESIDENCIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_PRESIDENCIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_PRESIDENCIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################
# CENTRAL TELEMARKETING
#192.168.105.16/28
v_VLAN_FAA_ADM_TELEMARKETING='192.168.105.16/28';		
v_VLAN_FAA_ADM_TELEMARKETING_ROTA='-net 192.168.105.0 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_TELEMARKETING(){
  route add $v_VLAN_FAA_ADM_TELEMARKETING_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_TELEMARKETING ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_TELEMARKETING(){
  route del $v_VLAN_FAA_ADM_TELEMARKETING_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_TELEMARKETING *[OK] \033[m ";
}

func_ENABLE_NET_ADM_TELEMARKETING(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_TELEMARKETING -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_TELEMARKETING(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_TELEMARKETING -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_TELEMARKETING_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_TELEMARKETING -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_TELEMARKETING_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_TELEMARKETING -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_TELEMARKETING(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_TELEMARKETING -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_TELEMARKETING -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_TELEMARKETING -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_TELEMARKETING -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_TELEMARKETING -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT
}
###########################################################################################################################################
# ARQUIVO
#192.168.105.32/28
v_VLAN_FAA_ADM_ARQUIVO='192.168.105.32/28';		
v_VLAN_FAA_ADM_ARQUIVO_ROTA='-net 192.168.105.32 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_ARQUIVO(){
  route add $v_VLAN_FAA_ADM_ARQUIVO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_ARQUIVO ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_ARQUIVO(){
  route del $v_VLAN_FAA_ADM_ARQUIVO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_ARQUIVO *[OK] \033[m ";
}

func_ENABLE_NET_ADM_ARQUIVO(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_ARQUIVO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_ARQUIVO(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_ARQUIVO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_ARQUIVO_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_ARQUIVO -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_ARQUIVO_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_ARQUIVO -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_ARQUIVO(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_ARQUIVO -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_ARQUIVO -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_ARQUIVO -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_ARQUIVO -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_ARQUIVO -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT
}
###########################################################################################################################################
# 1 ANDAR - PARTE 01
###########################################################################################################################################
# COMUNICACAO
#192.168.103.0/28
v_VLAN_FAA_ADM_COMUNICACAO='192.168.103.0/28';		# SubRede Comunicacao

v_IP_FAA_ADM_COMUNICACAO_H01='192.168.103.1';		# Comunicacao - Host 01
v_IP_FAA_ADM_COMUNICACAO_H02='192.168.103.2';		# Comunicacao - Host 02
v_IP_FAA_ADM_COMUNICACAO_H03='192.168.103.3';		# Comunicacao - Host 03
v_IP_FAA_ADM_COMUNICACAO_H04='192.168.103.4';		# Comunicacao - Host 04

v_VLAN_FAA_ADM_COMUNICACAO_ROTA='-net 192.168.103.0 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_COMUNICACAO(){
  route add $v_VLAN_FAA_ADM_COMUNICACAO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_COMUNICACAO ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_COMUNICACAO(){
  route del $v_VLAN_FAA_ADM_COMUNICACAO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_COMUNICACAO *[OK] \033[m ";
}

func_ENABLE_NET_ADM_COMUNICACAO(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_COMUNICACAO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_COMUNICACAO(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_COMUNICACAO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_COMUNICACAO_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_COMUNICACAO -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_COMUNICACAO_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_COMUNICACAO -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_COMUNICACAO(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_COMUNICACAO -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_COMUNICACAO -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_COMUNICACAO -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_COMUNICACAO -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_COMUNICACAO -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT
}
###########################################################################################################################################
# EXTENSAO
#192.168.103.16/28
v_VLAN_FAA_ADM_EXTENSAO='192.168.103.16/28';		
v_VLAN_FAA_ADM_EXTENSAO_ROTA='-net 192.168.103.16 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_EXTENSAO(){
  route add $v_VLAN_FAA_ADM_EXTENSAO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_EXTENSAO ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_EXTENSAO(){
  route del $v_VLAN_FAA_ADM_EXTENSAO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_EXTENSAO *[OK] \033[m ";
}

func_ENABLE_NET_ADM_EXTENSAO(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_EXTENSAO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_EXTENSAO(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_EXTENSAO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_EXTENSAO_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_EXTENSAO -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_EXTENSAO_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_EXTENSAO -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_EXTENSAO(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_EXTENSAO -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_EXTENSAO -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_EXTENSAO -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_EXTENSAO -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_EXTENSAO -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_EXTENSAO -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_EXTENSAO -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_EXTENSAO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_EXTENSAO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_EXTENSAO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_EXTENSAO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################
# AUDITORIO
#192.168.103.48/28
v_VLAN_FAA_ADM_AUDITORIO='192.168.103.48/28';		
v_VLAN_FAA_ADM_AUDITORIO_ROTA='-net 192.168.103.48 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_AUDITORIO(){
  route add $v_VLAN_FAA_ADM_AUDITORIO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_AUDITORIO ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_AUDITORIO(){
  route del $v_VLAN_FAA_ADM_AUDITORIO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_AUDITORIO *[OK] \033[m ";
}

func_ENABLE_NET_ADM_AUDITORIO(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_AUDITORIO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_AUDITORIO(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_AUDITORIO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_AUDITORIO_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_AUDITORIO -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_AUDITORIO_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_AUDITORIO -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_AUDITORIO(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_AUDITORIO -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_AUDITORIO -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_AUDITORIO -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_AUDITORIO -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_AUDITORIO -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT
}
###########################################################################################################################################
# DIRETORIA SOCIAL
#192.168.103.64/28
v_VLAN_FAA_ADM_DIRSOCIAL='192.168.103.64/28';		
v_VLAN_FAA_ADM_DIRSOCIAL_ROTA='-net 192.168.103.64 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_DIRSOCIAL(){
  route add $v_VLAN_FAA_ADM_DIRSOCIAL_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_DIRSOCIAL ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_DIRSOCIAL(){
  route del $v_VLAN_FAA_ADM_DIRSOCIAL_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_DIRSOCIAL *[OK] \033[m ";
}

func_ENABLE_NET_ADM_DIRSOCIAL(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_DIRSOCIAL -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_DIRSOCIAL(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_DIRSOCIAL -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_DIRSOCIAL_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_DIRSOCIAL -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_DIRSOCIAL_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_DIRSOCIAL -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_DIRSOCIAL(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_DIRSOCIAL -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DIRSOCIAL -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DIRSOCIAL -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_DIRSOCIAL -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_DIRSOCIAL -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT
}
###########################################################################################################################################
# RADIO
#192.168.103.80/28
v_VLAN_FAA_ADM_RADIO='192.168.103.80/28';		
v_VLAN_FAA_ADM_RADIO_ROTA='-net 192.168.103.80 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_RADIO(){
  route add $v_VLAN_FAA_ADM_RADIO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_RADIO ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_RADIO(){
  route del $v_VLAN_FAA_ADM_RADIO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_RADIO *[OK] \033[m ";
}

func_ENABLE_NET_ADM_RADIO(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_RADIO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_RADIO(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_RADIO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_RADIO_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_RADIO -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_RADIO_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_RADIO -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_RADIO(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_RADIO -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_RADIO -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_RADIO -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_RADIO -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_RADIO -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT
}
###########################################################################################################################################
# ADMINISTRACAO 1 ANDAR
###########################################################################################################################################
# SECRETARIA GERAL
#192.168.106.0/27
v_VLAN_FAA_ADM_SECGERAL='192.168.106.0/27';		
v_VLAN_FAA_ADM_SECGERAL_ROTA='-net 192.168.106.0 netmask 255.255.255.224';

func_ADICIONA_TABELA_ROTAS_ADM_SECGERAL(){
  route add $v_VLAN_FAA_ADM_SECGERAL_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_SECGERAL ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_SECGERAL(){
  route del $v_VLAN_FAA_ADM_SECGERAL_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_SECGERAL *[OK] \033[m ";
}

func_ENABLE_NET_ADM_SECGERAL(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_SECGERAL -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_SECGERAL(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_SECGERAL -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_SECGERAL_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_SECGERAL -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_SECGERAL_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_SECGERAL -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_SECGERAL(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_SECGERAL -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_SECGERAL -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_SECGERAL -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_SECGERAL -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_SECGERAL -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_SECGERAL -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_SECGERAL -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_SECGERAL -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_SECGERAL -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_SECGERAL -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_SECGERAL -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################
# ALMOXARIFADO
#192.168.106.32/28
v_VLAN_FAA_ADM_ALMOXARIFADO='192.168.106.32/28';		
v_VLAN_FAA_ADM_ALMOXARIFADO_ROTA='-net 192.168.106.32 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_ALMOXARIFADO(){
  route add $v_VLAN_FAA_ADM_ALMOXARIFADO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_ALMOXARIFADO ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_ALMOXARIFADO(){
  route del $v_VLAN_FAA_ADM_ALMOXARIFADO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_ALMOXARIFADO *[OK] \033[m ";
}

func_ENABLE_NET_ADM_ALMOXARIFADO(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_ALMOXARIFADO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_ALMOXARIFADO(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_ALMOXARIFADO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_ALMOXARIFADO_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_ALMOXARIFADO -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_ALMOXARIFADO_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_ALMOXARIFADO -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_ALMOXARIFADO(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_ALMOXARIFADO -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_ALMOXARIFADO -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_ALMOXARIFADO -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_ALMOXARIFADO -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_ALMOXARIFADO -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT
}
###########################################################################################################################################
# TELEFONIA
#192.168.106.48/28
v_VLAN_FAA_ADM_TELEFONIA='192.168.106.48/28';		
v_VLAN_FAA_ADM_TELEFONIA_ROTA='-net 192.168.106.48 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_TELEFONIA(){
  route add $v_VLAN_FAA_ADM_TELEFONIA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_TELEFONIA ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_TELEFONIA(){
  route del $v_VLAN_FAA_ADM_TELEFONIA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_TELEFONIA *[OK] \033[m ";
}

func_ENABLE_NET_ADM_TELEFONIA(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_TELEFONIA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_TELEFONIA(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_TELEFONIA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_TELEFONIA_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_TELEFONIA -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_TELEFONIA_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_TELEFONIA -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_TELEFONIA(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_TELEFONIA -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_TELEFONIA -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_TELEFONIA -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_TELEFONIA -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_TELEFONIA -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT
}
###########################################################################################################################################
# PROTOCOLO
#192.168.106.64/28
v_VLAN_FAA_ADM_PROTOCOLO='192.168.106.64/28';		
v_VLAN_FAA_ADM_PROTOCOLO_ROTA='-net 192.168.106.64 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_PROTOCOLO(){
  route add $v_VLAN_FAA_ADM_PROTOCOLO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_PROTOCOLO ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_PROTOCOLO(){
  route del $v_VLAN_FAA_ADM_PROTOCOLO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_PROTOCOLO *[OK] \033[m ";
}

func_ENABLE_NET_ADM_PROTOCOLO(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_PROTOCOLO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_PROTOCOLO(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_PROTOCOLO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_PROTOCOLO_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_PROTOCOLO -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_PROTOCOLO_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_PROTOCOLO -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_PROTOCOLO(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_PROTOCOLO -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_PROTOCOLO -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_PROTOCOLO -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_PROTOCOLO -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_PROTOCOLO -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_PROTOCOLO -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_PROTOCOLO -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_PROTOCOLO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_PROTOCOLO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_PROTOCOLO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_PROTOCOLO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################
# POS GRADUACAO
#192.168.106.80/28
v_VLAN_FAA_ADM_POSGRADUACAO='192.168.106.80/28';		
v_VLAN_FAA_ADM_POSGRADUACAO_ROTA='-net 192.168.106.80 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_POSGRADUACAO(){
  route add $v_VLAN_FAA_ADM_POSGRADUACAO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_POSGRADUACAO ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_POSGRADUACAO(){
  route del $v_VLAN_FAA_ADM_POSGRADUACAO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_POSGRADUACAO *[OK] \033[m ";
}

func_ENABLE_NET_ADM_POSGRADUACAO(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_POSGRADUACAO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_POSGRADUACAO(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_POSGRADUACAO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_POSGRADUACAO_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_POSGRADUACAO -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_POSGRADUACAO_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_POSGRADUACAO -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_POSGRADUACAO(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_POSGRADUACAO -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_POSGRADUACAO -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_POSGRADUACAO -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_POSGRADUACAO -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_POSGRADUACAO -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_POSGRADUACAO -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_POSGRADUACAO -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_POSGRADUACAO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_POSGRADUACAO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_POSGRADUACAO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_POSGRADUACAO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################	
# CONTROLE DE MENSALIDADE
#192.168.106.96/28	
v_VLAN_FAA_ADM_CTRLMENSALIDADE='192.168.106.96/28';	
	
v_IP_FAA_ADM_CTRLMENSALIDADE_H01='192.168.106.97'; 	

v_VLAN_FAA_ADM_CTRLMENSALIDADE_ROTA='-net 192.168.106.96 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_CTRLMENSALIDADE(){
  route add $v_VLAN_FAA_ADM_CTRLMENSALIDADE_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_CTRLMENSALIDADE ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_CTRLMENSALIDADE(){
  route del $v_VLAN_FAA_ADM_CTRLMENSALIDADE_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_CTRLMENSALIDADE *[OK] \033[m ";
}

func_ENABLE_NET_ADM_CTRLMENSALIDADE(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_CTRLMENSALIDADE -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_CTRLMENSALIDADE(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_CTRLMENSALIDADE -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_CTRLMENSALIDADE_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_CTRLMENSALIDADE -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_CTRLMENSALIDADE_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_CTRLMENSALIDADE -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_CTRLMENSALIDADE(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_CTRLMENSALIDADE -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CTRLMENSALIDADE -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CTRLMENSALIDADE -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_CTRLMENSALIDADE -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_CTRLMENSALIDADE -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CTRLMENSALIDADE -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_CTRLMENSALIDADE -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_CTRLMENSALIDADE -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_CTRLMENSALIDADE -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CTRLMENSALIDADE -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CTRLMENSALIDADE -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

func_VLAN_FAA_ADM_CTRLMENSALIDADE_SKYLINE(){
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_CTRLMENSALIDADE_H01 -d 0/0 --dport 8800 -j ACCEPT
}

###########################################################################################################################################
# TESOURARIA
#192.168.106.112/28
v_VLAN_FAA_ADM_TESOURARIA='192.168.106.112/28';		
v_VLAN_FAA_ADM_TESOURARIA_ROTA='-net 192.168.106.112 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_TESOURARIA(){
  route add $v_VLAN_FAA_ADM_TESOURARIA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_TESOURARIA ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_TESOURARIA(){
  route del $v_VLAN_FAA_ADM_TESOURARIA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_TESOURARIA *[OK] \033[m ";
}

func_ENABLE_NET_ADM_TESOURARIA(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_TESOURARIA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_TESOURARIA(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_TESOURARIA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_TESOURARIA_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_TESOURARIA -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_TESOURARIA_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_TESOURARIA -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_TESOURARIA(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_TESOURARIA -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_TESOURARIA -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_TESOURARIA -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_TESOURARIA -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_TESOURARIA -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_TESOURARIA -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_TESOURARIA -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_TESOURARIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_TESOURARIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_TESOURARIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_TESOURARIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################
# ADMINISTRACAO 2 ANDAR
###########################################################################################################################################
# CONTABILIDADE
# 192.168.104.0/28
v_VLAN_FAA_ADM_CONTABILIDADE='192.168.104.0/28';	# SubRede Contabilidade

v_IP_FAA_ADM_CONTABILIDADE_H01='192.168.104.1';	# Contabilidade - Host 01
v_IP_FAA_ADM_CONTABILIDADE_H02='192.168.104.2';	# Contabilidade - Host 02
v_IP_FAA_ADM_CONTABILIDADE_H03='192.168.104.3';	# Contabilidade - Host 03
v_IP_FAA_ADM_CONTABILIDADE_H04='192.168.104.4';	# Contabilidade - Host 04

v_VLAN_FAA_ADM_CONTABILIDADE_ROTA='-net 192.168.104.0 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_CONTABILIDADE(){
  route add $v_VLAN_FAA_ADM_CONTABILIDADE_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_CONTABILIDADE ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_CONTABILIDADE(){
  route del $v_VLAN_FAA_ADM_CONTABILIDADE_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_CONTABILIDADE *[OK] \033[m ";
}

func_ENABLE_NET_ADM_CONTABILIDADE(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_CONTABILIDADE -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_CONTABILIDADE(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_CONTABILIDADE -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_CONTABILIDADE_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_CONTABILIDADE -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_CONTABILIDADE_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_CONTABILIDADE -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_CONTABILIDADE(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

func_VLAN_FAA_ADM_CONTABILIDADE_EXTRA(){
	
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_SERVIDOR_FAA_PROSO --dport 3389 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_SERVIDOR_FAA_PROSO --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_SERVIDOR_FAA_PROSO --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_SERVIDOR_FAA_PROSO --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_SERVIDOR_FAA_PROSO --dport 445 -j ACCEPT

  # portas pervasive sql
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_SERVIDOR_FAA_PROSO --dport 1583 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_SERVIDOR_FAA_PROSO --dport 3351 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_SERVIDOR_FAA_PROSO --dport 8080 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_SERVIDOR_FAA_PROSO --dport 1433 -j ACCEPT

  # acesso remoto prosoft
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d 0/0 --dport $v_PORTAS_PSOFT -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d 0/0 --dport 35142 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CONTABILIDADE -d 0/0 --dport 35143 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_CONTABILIDADE -d $v_IP_FAA_ADM_CONTABILIDADE_H04 -j ACCEPT

}
###########################################################################################################################################
# DEPARTAMENTO PESSOAL
#192.168.104.16/28
v_VLAN_FAA_ADM_DPESSOAL='192.168.104.16/28';		# SubRede DPessoal

v_IP_FAA_ADM_DPESSOAL_H01='192.168.52.9';		# DPessoal - Host 01
v_IP_FAA_ADM_DPESSOAL_H02='192.168.52.10';		# DPessoal - Host 02
v_IP_FAA_ADM_DPESSOAL_H03='192.168.52.11';		# DPessoal - Host 03
v_IP_FAA_ADM_DPESSOAL_H04='192.168.52.12';		# DPessoal - Host 04	

v_VLAN_FAA_ADM_DPESSOAL_ROTA='-net 192.168.104.16 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_DPESSOAL(){
  route add $v_VLAN_FAA_ADM_DPESSOAL_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_DPESSOAL ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_DPESSOAL(){
  route del $v_VLAN_FAA_ADM_DPESSOAL_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_DPESSOAL *[OK] \033[m ";
}

func_ENABLE_NET_ADM_DPESSOAL(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_DPESSOAL -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_DPESSOAL(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_DPESSOAL -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_DPESSOAL_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_DPESSOAL -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_DPESSOAL_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_DPESSOAL -o ppp0 -j MASQUERADE
}
  
func_VLAN_FAA_ADM_DPESSOAL(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

func_VLAN_FAA_ADM_DPESSOAL_EXTRA(){
  $v_CMD_IPTABLES -A FORWARD -s 192.168.52.9 -d $v_ALL_NETWORKS -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s 192.168.52.12 -d $v_ALL_NETWORKS -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s 192.168.52.11 -d $v_ALL_NETWORKS -j ACCEPT
	
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_SERVIDOR_FAA_PROSO --dport 3389 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_SERVIDOR_FAA_PROSO --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_SERVIDOR_FAA_PROSO --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_SERVIDOR_FAA_PROSO --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_SERVIDOR_FAA_PROSO --dport 445 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_FAA_ADM_CONTABILIDADE_H04 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_SERVIDOR_FAA_PROSO --dport 1583 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_SERVIDOR_FAA_PROSO --dport 3351 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_SERVIDOR_FAA_PROSO --dport 8080 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_SERVIDOR_FAA_PROSO --dport 1433 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_DPESSOAL -d $v_IP_FAA_ADM_CONTABILIDADE_H04 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d 161.148.173.128 --dport 443 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d 189.127.3.11 --dport 35001:35101 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d 0/0 --dport 443 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d 0/0 --dport 3456 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d 0/0 --dport 5017 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d 0/0 --dport 5022 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_DPESSOAL -d 0/0 --dport 21 -j ACCEPT
}

func_VLAN_FAA_ADM_LIBERA_RAIS(){
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H01 -d 161.148.173.128 --dport 443 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H03 -d 161.148.173.128 --dport 443 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H04 -d 161.148.173.128 --dport 443 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H03 -d 189.127.3.11 --dport 35001:35101 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H04 -d 189.127.3.11 --dport 35000:36000 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s 10.10.10.69 -d 189.127.3.11 --dport 35001:35101 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H04 -d 0/0 --dport 443 -j ACCEPT
  # reiceita Net
  #$v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H04 --sport $v_PORTAS_ALTAS -d 161.148.0.0/16 --dport 3456 -j ACCEPT
  #$v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H04 --sport $v_PORTAS_ALTAS -d 200.198.239.0/16 --dport 3456 -j ACCEPT
  #$v_CMD_IPTABLES -A FORWARD -p tcp -d $v_IP_FAA_ADM_DPESSOAL_H04 --dport $v_PORTAS_ALTAS -s 161.148.0.0/16 --sport 3456 -j ACCEPT
  #$v_CMD_IPTABLES -A FORWARD -p tcp -d $v_IP_FAA_ADM_DPESSOAL_H04 --dport $v_PORTAS_ALTAS -s 200.198.239.0/16 --sport 3456 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H03 --sport $v_PORTAS_ALTAS -d 0/0 --dport 3456 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H03 --sport $v_PORTAS_ALTAS -d 0/0 --dport 3456 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -d $v_IP_FAA_ADM_DPESSOAL_H03 --dport $v_PORTAS_ALTAS -s 0/0 --sport 3456 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -d $v_IP_FAA_ADM_DPESSOAL_H03 --dport $v_PORTAS_ALTAS -s 0/0 --sport 3456 -j ACCEPT
}

func_VLAN_FAA_ADM_RH_04(){
  #$v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H04 -d 200.152.32.148 --dport 5017 -j ACCEPT
  #$v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H04 -d 200.152.32.148 --dport 5022 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H04 -d 0/0 --dport 5017 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H04 -d 0/0 --dport 5022 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H04 -d 200.152.32.148 --dport 21 -j ACCEPT
}

func_VLAN_FAA_ADM_LIBERA_RECEITANET(){
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H01 -d 0/0 --dport 3456 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H03 -d 0/0 --dport 3456 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H04 -d 0/0 --dport 3456 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_IP_FAA_ADM_DPESSOAL_H01 -d 0/0 --dport 443 -j ACCEPT
}
###########################################################################################################################################
# NEGOCIAÇÃO
# 192.168.105.32/28
v_VLAN_FAA_ADM_NEGOCIACAO='192.168.105.32/28';		

v_IP_FAA_ADM_NEGOCIACAO_H01='192.168.105.33';		# NEGOCIACAO - Host 01
v_IP_FAA_ADM_NEGOCIACAO_H02='192.168.105.34';		# NEGOCIACAO - Host 02

v_VLAN_FAA_ADM_NEGOCIACAO_ROTA='-net 192.168.104.16 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_NEGOCIACAO(){
  route add $v_VLAN_FAA_ADM_NEGOCIACAO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_NEGOCIACAO ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_NEGOCIACAO(){
  route del $v_VLAN_FAA_ADM_NEGOCIACAO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_NEGOCIACAO *[OK] \033[m ";
}

func_ENABLE_NET_ADM_NEGOCIACAO(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_NEGOCIACAO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_COMUNICACAO(){
  $v_CMD_IPTABLES -t nat -D NEGOCIACAO -s $v_VLAN_FAA_ADM_NEGOCIACAO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_NEGOCIACAO_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_NEGOCIACAO -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_NEGOCIACAO_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_NEGOCIACAO -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_NEGOCIACAO(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_NEGOCIACAO -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_NEGOCIACAO -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_NEGOCIACAO -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_NEGOCIACAO -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_NEGOCIACAO -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_NEGOCIACAO -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_NEGOCIACAO -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_NEGOCIACAO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_NEGOCIACAO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_NEGOCIACAO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_NEGOCIACAO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
)

###########################################################################################################################################
# ENGENHARIA/MANUTENCAO
#192.168.104.48/28
v_VLAN_FAA_ADM_ENGENHARIA='192.168.104.48/28';		
v_VLAN_FAA_ADM_ENGENHARIA_ROTA='-net 192.168.104.48 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_ENGENHARIA(){
  route add $v_VLAN_FAA_ADM_ENGENHARIA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_ENGENHARIA ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_ENGENHARIA(){
  route del $v_VLAN_FAA_ADM_ENGENHARIA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_ENGENHARIA *[OK] \033[m ";
}

func_ENABLE_NET_ADM_ENGENHARIA(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_ENGENHARIA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_ENGENHARIA(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_ENGENHARIA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_ENGENHARIA_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_ENGENHARIA -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_ENGENHARIA_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_ENGENHARIA -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_ENGENHARIA(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_ENGENHARIA -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_ENGENHARIA -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_ENGENHARIA -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_ENGENHARIA -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_ENGENHARIA -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT
}
###########################################################################################################################################
# FILANTROPIA
#192.168.104.64/28
v_VLAN_FAA_ADM_FILANTROPIA='192.168.104.64/28';		
v_VLAN_FAA_ADM_FILANTROPIA_ROTA='-net 192.168.104.64 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_FILANTROPIA(){
  route add $v_VLAN_FAA_ADM_FILANTROPIA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_FILANTROPIA ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_FILANTROPIA(){
  route del $v_VLAN_FAA_ADM_FILANTROPIA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_FILANTROPIA *[OK] \033[m ";
}

func_ENABLE_NET_ADM_FILANTROPIA(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_FILANTROPIA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_FILANTROPIA(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_FILANTROPIA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_FILANTROPIA_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_FILANTROPIA -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_FILANTROPIA_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_FILANTROPIA -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_FILANTROPIA(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_FILANTROPIA -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_FILANTROPIA -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_FILANTROPIA -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_FILANTROPIA -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_FILANTROPIA -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_FILANTROPIA -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_FILANTROPIA -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_FILANTROPIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_FILANTROPIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_FILANTROPIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_FILANTROPIA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################
# COMPRAS
#192.168.104.80/28
v_VLAN_FAA_ADM_COMPRAS='192.168.104.80/28';		
v_VLAN_FAA_ADM_COMPRAS_ROTA='-net 192.168.104.80 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_COMPRAS(){
  route add $v_VLAN_FAA_ADM_COMPRAS_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_COMPRAS ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_COMPRAS(){
  route del $v_VLAN_FAA_ADM_COMPRAS_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_COMPRAS *[OK] \033[m ";
}

func_ENABLE_NET_ADM_COMPRAS(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_COMPRAS -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_COMPRAS(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_COMPRAS -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_COMPRAS_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_COMPRAS -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_COMPRAS_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_COMPRAS -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_COMPRAS(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_COMPRAS -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_COMPRAS -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_COMPRAS -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_COMPRAS -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_COMPRAS -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_COMPRAS -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_COMPRAS -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_COMPRAS -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_COMPRAS -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_COMPRAS -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_COMPRAS -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}
###########################################################################################################################################
# VIGILANCIA
#192.168.104.96/28
v_VLAN_FAA_ADM_VIGILANCIA='192.168.104.96/28';		
v_VLAN_FAA_ADM_VIGILANCIA_ROTA='-net 192.168.104.96 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_VIGILANCIA(){
  route add $v_VLAN_FAA_ADM_VIGILANCIA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_VIGILANCIA ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_VIGILANCIA(){
  route del $v_VLAN_FAA_ADM_VIGILANCIA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_VIGILANCIA *[OK] \033[m ";
}

func_ENABLE_NET_ADM_VIGILANCIA(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_VIGILANCIA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_VIGILANCIA(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_VIGILANCIA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_VIGILANCIA_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_VIGILANCIA -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_VIGILANCIA_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_VIGILANCIA -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_VIGILANCIA(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_VIGILANCIA -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_VIGILANCIA -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_VIGILANCIA -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_VIGILANCIA -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_VIGILANCIA -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT
}
###########################################################################################################################################
# JURIDICO
#192.168.104.112/28
v_VLAN_FAA_ADM_JURIDICO='192.168.104.112/28';		
v_VLAN_FAA_ADM_JURIDICO_ROTA='-net 192.168.104.112 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_JURIDICO(){
  route add $v_VLAN_FAA_ADM_JURIDICO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_JURIDICO ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_JURIDICO(){
  route del $v_VLAN_FAA_ADM_JURIDICO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_JURIDICO *[OK] \033[m ";
}

func_ENABLE_NET_ADM_JURIDICO(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_JURIDICO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_JURIDICO(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_JURIDICO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_JURIDICO_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_JURIDICO -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_JURIDICO_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_JURIDICO -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_JURIDICO(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_JURIDICO -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_JURIDICO -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_JURIDICO -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_JURIDICO -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_JURIDICO -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_JURIDICO -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_JURIDICO -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_JURIDICO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_JURIDICO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_JURIDICO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_JURIDICO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################
# PATRIMONIO
#192.168.104.128/28
v_VLAN_FAA_ADM_PATRIMONIO='192.168.104.128/28';		
v_VLAN_FAA_ADM_PATRIMONIO_ROTA='-net 192.168.104.128 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_PATRIMONIO(){
  route add $v_VLAN_FAA_ADM_PATRIMONIO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_PATRIMONIO ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_PATRIMONIO(){
  route del $v_VLAN_FAA_ADM_PATRIMONIO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_PATRIMONIO *[OK] \033[m ";
}

func_ENABLE_NET_ADM_PATRIMONIO(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_PATRIMONIO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_PATRIMONIO(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_PATRIMONIO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_PATRIMONIO_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_PATRIMONIO -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_PATRIMONIO_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_PATRIMONIO -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_PATRIMONIO(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_PATRIMONIO -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_PATRIMONIO -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_PATRIMONIO -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_PATRIMONIO -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_PATRIMONIO -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_PATRIMONIO -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_PATRIMONIO -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_PATRIMONIO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_PATRIMONIO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_PATRIMONIO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_PATRIMONIO -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}
###########################################################################################################################################
# HIGENIZACAO
#192.168.104.144/28
v_VLAN_FAA_ADM_HIGENIZACAO='192.168.104.144/28';		
v_VLAN_FAA_ADM_HIGENIZACAO_ROTA='-net 192.168.104.144 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_HIGENIZACAO(){
  route add $v_VLAN_FAA_ADM_HIGENIZACAO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_HIGENIZACAO ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_HIGENIZACAO(){
  route del $v_VLAN_FAA_ADM_HIGENIZACAO_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_HIGENIZACAO *[OK] \033[m ";
}

func_ENABLE_NET_ADM_HIGENIZACAO(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_HIGENIZACAO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_HIGENIZACAO(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_HIGENIZACAO -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_HIGENIZACAO_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_HIGENIZACAO -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_HIGENIZACAO_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_HIGENIZACAO -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_HIGENIZACAO(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_HIGENIZACAO -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_HIGENIZACAO -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_HIGENIZACAO -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_HIGENIZACAO -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_HIGENIZACAO -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT
}

###########################################################################################################################################
# CESVA
#192.168.107.0/28
v_VLAN_FAA_ADM_CESVA='192.168.107.0/28';		
v_VLAN_FAA_ADM_CESVA_ROTA='-net 192.168.107.0 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_CESVA(){
  route add $v_VLAN_FAA_ADM_CESVA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_CESVA ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_CESVA(){
  route del $v_VLAN_FAA_ADM_CESVA_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_CESVA *[OK] \033[m ";
}

func_ENABLE_NET_ADM_CESVA(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_CESVA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_CESVA(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_CESVA -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_CESVA_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_CESVA -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_CESVA_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_CESVA -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_CESVA(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_CESVA -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CESVA -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CESVA -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_CESVA -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_CESVA -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CESVA -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_CESVA -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_CESVA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_CESVA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CESVA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CESVA -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################
# SAO JOSE
#192.168.107.16/28
v_VLAN_FAA_ADM_CASAOJOSE='192.168.107.16/28';		
v_VLAN_FAA_ADM_CASAOJOSE_ROTA='-net 192.168.107.16 netmask 255.255.255.240';

func_ADICIONA_TABELA_ROTAS_ADM_CASAOJOSE(){
  route add $v_VLAN_FAA_ADM_CASAOJOSE_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_CASAOJOSE ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_CASAOJOSE(){
  route del $v_VLAN_FAA_ADM_CASAOJOSE_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_CASAOJOSE *[OK] \033[m ";
}

func_ENABLE_NET_ADM_CASAOJOSE(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_CASAOJOSE -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_CASAOJOSE(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_CASAOJOSE -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_CASAOJOSE_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_CASAOJOSE -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_CASAOJOSE_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_CASAOJOSE -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_CASAOJOSE(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_CASAOJOSE -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CASAOJOSE -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CASAOJOSE -d $v_IP_SERVIDOR_FAA_ADNTI --dport 5222 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_CASAOJOSE -d $v_IP_IMPRESSORA_FAA_IMP02 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_CASAOJOSE -d $v_IP_IMPRESSORA_FAA_IMP03 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CASAOJOSE -d $v_IP_SERVIDOR_FAA_INTRA --dport 80 -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -s $v_VLAN_FAA_ADM_CASAOJOSE -d $v_IP_SERVIDOR_FAA_DADOS -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_CASAOJOSE -d $v_IP_SERVIDOR_FAA_ADMIN --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_CASAOJOSE -d $v_IP_SERVIDOR_FAA_ADMIN --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CASAOJOSE -d $v_IP_SERVIDOR_FAA_ADMIN --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_CASAOJOSE -d $v_IP_SERVIDOR_FAA_ADMIN --dport 445 -j ACCEPT
}

###########################################################################################################################################

###########################################################################################################################################
# LABORATORIOS DE INFORMATICA

#192.168.1.0/26
v_VLAN_FAA_ADM_LAB01='192.168.1.0/26';		
v_VLAN_FAA_ADM_LAB01_ROTA='-net 192.168.1.0 netmask 255.255.255.192';

func_ADICIONA_TABELA_ROTAS_ADM_LAB01(){
  route add $v_VLAN_FAA_ADM_LAB01_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_LAB01 ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_LAB01(){
  route del $v_VLAN_FAA_ADM_LAB01_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_LAB01 *[OK] \033[m ";
}

func_ENABLE_NET_ADM_LAB01(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_LAB01 -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_LAB01(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_LAB01 -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_LAB01_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_LAB01 -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_LAB01_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_LAB01 -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_LAB01(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_LAB01 -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_LAB01 -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_LAB01 -d $v_IP_SERVIDOR_FAA_ACADE --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_LAB01 -d $v_IP_SERVIDOR_FAA_ACADE --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_LAB01 -d $v_IP_SERVIDOR_FAA_ACADE --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_LAB01 -d $v_IP_SERVIDOR_FAA_ACADE --dport 445 -j ACCEPT
}
###########################################################################################################################################
# LABORATORIO 02 
#192.168.2.0/26
v_VLAN_FAA_ADM_LAB02='192.168.2.0/26';		
v_VLAN_FAA_ADM_LAB02_ROTA='-net 192.168.2.0 netmask 255.255.255.192';

func_ADICIONA_TABELA_ROTAS_ADM_LAB02(){
  route add $v_VLAN_FAA_ADM_LAB02_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_LAB02 ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_LAB02(){
  route del $v_VLAN_FAA_ADM_LAB02_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_LAB02 *[OK] \033[m ";
}

func_ENABLE_NET_ADM_LAB02(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_LAB02 -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_LAB02(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_LAB02 -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_LAB02_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_LAB02 -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_LAB02_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_LAB02 -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_LAB02(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_LAB02 -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_LAB02 -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_LAB02 -d $v_IP_SERVIDOR_FAA_ACADE --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_LAB02 -d $v_IP_SERVIDOR_FAA_ACADE --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_LAB02 -d $v_IP_SERVIDOR_FAA_ACADE --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_LAB02 -d $v_IP_SERVIDOR_FAA_ACADE --dport 445 -j ACCEPT
}
###########################################################################################################################################
# LABORATORIO 03 
#192.168.3.0/26
v_VLAN_FAA_ADM_LAB03='192.168.3.0/26';		
v_VLAN_FAA_ADM_LAB03_ROTA='-net 192.168.3.0 netmask 255.255.255.192';

func_ADICIONA_TABELA_ROTAS_ADM_LAB03(){
  route add $v_VLAN_FAA_ADM_LAB03_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_LAB03 ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_LAB03(){
  route del $v_VLAN_FAA_ADM_LAB03_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_LAB03 *[OK] \033[m ";
}

func_ENABLE_NET_ADM_LAB03(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_LAB03 -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_LAB03(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_LAB03 -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_LAB03_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_LAB03 -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_LAB03_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_LAB03 -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_LAB03(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_LAB03 -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_LAB03 -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_LAB03 -d $v_IP_SERVIDOR_FAA_ACADE --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_LAB03 -d $v_IP_SERVIDOR_FAA_ACADE --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_LAB03 -d $v_IP_SERVIDOR_FAA_ACADE --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_LAB03 -d $v_IP_SERVIDOR_FAA_ACADE --dport 445 -j ACCEPT
}
###########################################################################################################################################
# LABORATORIO 04
#192.168.4.0/26
v_VLAN_FAA_ADM_LAB04='192.168.4.0/26';		
v_VLAN_FAA_ADM_LAB04_ROTA='-net 192.168.4.0 netmask 255.255.255.192';

func_ADICIONA_TABELA_ROTAS_ADM_LAB04(){
  route add $v_VLAN_FAA_ADM_LAB04_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_LAB04 ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_LAB04(){
  route del $v_VLAN_FAA_ADM_LAB04_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_LAB04 *[OK] \033[m ";
}

func_ENABLE_NET_ADM_LAB04(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_LAB04 -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_LAB04(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_LAB04 -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_LAB04_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_LAB04 -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_LAB04_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_LAB04 -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_LAB04(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_LAB04 -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_LAB04 -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_LAB04 -d $v_IP_SERVIDOR_FAA_ACADE --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_LAB04 -d $v_IP_SERVIDOR_FAA_ACADE --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_LAB04 -d $v_IP_SERVIDOR_FAA_ACADE --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_LAB04 -d $v_IP_SERVIDOR_FAA_ACADE --dport 445 -j ACCEPT
}
###########################################################################################################################################
# LABORATORIO 05 
#192.168.5.0/26
v_VLAN_FAA_ADM_LAB05='192.168.5.0/26';		
v_VLAN_FAA_ADM_LAB05_ROTA='-net 192.168.5.0 netmask 255.255.255.192';

func_ADICIONA_TABELA_ROTAS_ADM_LAB05(){
  route add $v_VLAN_FAA_ADM_LAB05_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_LAB05 ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_LAB05(){
  route del $v_VLAN_FAA_ADM_LAB05_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_LAB05 *[OK] \033[m ";
}

func_ENABLE_NET_ADM_LAB05(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_LAB05 -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_LAB05(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_LAB05 -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_LAB05_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_LAB05 -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_LAB05_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_LAB05 -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_LAB05(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_LAB05 -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_LAB05 -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT

  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_LAB05 -d $v_IP_SERVIDOR_FAA_ACADE --dport 137 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_LAB05 -d $v_IP_SERVIDOR_FAA_ACADE --dport 138 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_LAB05 -d $v_IP_SERVIDOR_FAA_ACADE --dport 139 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_LAB05 -d $v_IP_SERVIDOR_FAA_ACADE --dport 445 -j ACCEPT
}

############################################################################
# WIRLESS
############################################################################
#192.168.200.0/26
v_VLAN_FAA_ADM_WIFI='192.168.200.0/26';		
v_VLAN_FAA_ADM_WIFI_ROTA='-net 192.168.200.0 netmask 255.255.255.192';

func_ADICIONA_TABELA_ROTAS_ADM_WIFI(){
  route add $v_VLAN_FAA_ADM_WIFI_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota criada para Rede -> $v_VLAN_FAA_ADM_WIFI ***[OK] \033[m ";
}
func_REMOVE_TABELA_ROTAS_ADM_WIFI(){
  route del $v_VLAN_FAA_ADM_WIFI_ROTA gw $v_IP_SERVIDOR_FAA_ADM_GATEWAY dev eth0
  echo "\033[34m Rota removida para Rede -> $v_VLAN_FAA_ADM_WIFI *[OK] \033[m ";
}

func_ENABLE_NET_ADM_WIFI(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_WIFI -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_DISABLE_NET_ADM_WIFI(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_WIFI -o $v_ETH1_INTERFACE_NET -j SNAT --to $v_IP_INTERFACE_NET
}
func_ENABLE_NET_ADM_WIFI_VELOX(){
  $v_CMD_IPTABLES -t nat -A POSTROUTING -s $v_VLAN_FAA_ADM_WIFI -o ppp0 -j MASQUERADE
}
func_DISABLE_NET_ADM_WIFI_VELOX(){
  $v_CMD_IPTABLES -t nat -D POSTROUTING -s $v_VLAN_FAA_ADM_WIFI -o ppp0 -j MASQUERADE
}

func_VLAN_FAA_ADM_WIFI(){
  $v_CMD_IPTABLES -A FORWARD -p udp -s $v_VLAN_FAA_ADM_WIFI -d $v_ALL_NETWORKS --dport 53 -j ACCEPT
  $v_CMD_IPTABLES -A FORWARD -p tcp -s $v_VLAN_FAA_ADM_WIFI -d $v_ALL_NETWORKS --dport $v_PORTA_PROXY -j ACCEPT
}
#################################################################
# FIM DA CRIAÇÃO DE REGRAS
#################################################################
#################################################################
# INICIO DO CONTROLE DAS REGRAS CRIADAS
#################################################################

case $1 in
  start)
    echo -e "\033[34m Criando variáveis******************************* [OK] \033[m ";
    echo -e "\033[34m Criando funções globais ************************ [OK] \033[m ";
   
    #################################################################
    #################################################################

    #################################################################
    # estabilizando conexoes


    #################################################################
    # bloqueios extras

    #################################################################
    # habilitando internet

    #################################################################
    # Ativando redirecionamentos

    
    echo -e "\033[34m ************************************************ [OK] \033[m ";
    echo -e "\033[34m ************** FIREWALL ATIVADO **************** [OK] \033[m ";
    echo -e "\033[34m ************************************************ [OK] \033[m ";
  ;;
  --enable-log)
    echo -e "\033[34m Ativando gravação de LOG *********************** [OK] \033[m ";
    func_LOG_YES
  ;;
  --disable-log)
    echo -e "\033[34m Removendo gravação de LOG ********************** [OK] \033[m ";
    func_LOG_NO
  ;;

  #################################################################
  # STOP
  #################################################################
  stop)
    echo -e "\033[34m Identifique-se [OK] \033[m ";
    func_VERIFICA_USER
    #func_GRAVA_LOG $1
    func_CLEAR_RULES
    func_POLICY_ACCEPT

    echo -e "\033[31m FIREWALL DESATIVADO **************************** [OK] \033[m ";
  ;;
  --list-filter)
    $v_CMD_IPTABLES -nL --line-number | more
  ;;
  --stat-filter)
    $v_CMD_IPTABLES -nL -v --line-number | more
  ;;
  --list-nat) 
    $v_CMD_IPTABLES -nL -t nat --line-number | more
  ;;
  --stat-nat) 
    $v_CMD_IPTABLES -nL -v -t nat --line-number | more
  ;;
  --list-mangle) 
    $v_CMD_IPTABLES -nL -t mangle --line-number | more
  ;;
  --stat-mangle) 
    $v_CMD_IPTABLES -nL -v -t mangle --line-number | more
  ;;
  #################################################################
  # RESTART
  #################################################################
  restart) 
    $0 stop
    $0 start
  ;;
  # Chamada de funções para controle de acesso a INTERNET
  --enable-net-adm)
    func_ENABLE_NET_ADM
  ;;
  --disable-net-adm)
    func_DISABLE_NET_ADM
  ;;
  --enable-net-acd)
    func_ENABLE_NET_ACD
  ;;
  --disable-net-acd)
    func_DISABLE_NET_ACD
  ;;
  --clear-rules)
    func_CLEAR_RULES
  ;;
  --velox)
    func_DISABLE_NET_ADM
    func_ENABLE_NET_ADM_VELOX
  ;;
  --linkx)
    func_ENABLE_NET_ADM
    func_DISABLE_NET_ADM_VELOX
    ifconfig ppp0 down
  ;;
  --add-redirect-prosoft)
    func_ADICIONA_REDIRECIONAMENTO_TS_PROSOFT
  ;;
  --del-redirect-prosoft)
    func_REMOVE_REDIRECIONAMENTO_TS_PROSOFT
  ;;
  #################################################################
  # HELP
  #################################################################
  --help)
    clear;
    echo "#################################################################"
    echo "# FIREWALL - LISTA DE OPÇÕES                                    #"
    echo "#################################################################"
    echo "# start - Ativa o firewall com politica DROP                    #"
    echo "# stop - Para completamente o Firewall ( cuidado )              #"
    echo "# restart - Reinicia o Firewall ( cuidado )                     #"
    echo "#---------------------------------------------------------------#"
    echo "# --enable-log - Para completamente o Firewall ( cuidado )      #"
    echo "# --disable-log - Para completamente o Firewall ( cuidado )     #"
    echo "#---------------------------------------------------------------#"
    echo "# --enable-receita  - Para completamente o Firewall ( cuidado ) #"
    echo "# --disable-receita  - Para completamente o Firewall ( cuidado )#"
    echo "#---------------------------------------------------------------#"
    echo "# --list-filter - Mostra regras na talela filter                #"
    echo "# --stat-filter - Mostra estatisticas da tabela filter          #"
    echo "# --list-nat - Mostra regras na talela nat                      #"
    echo "# --stat-nat - Mostra estatisticas da tabela nat                #"
    echo "# --list-mangle - Mostra regras na talela mangle                #"
    echo "# --stat-mangle - Mostra estatisticas da tabela mangle          #"
    echo "#---------------------------------------------------------------#"
    echo "# --enable-net-adm - Ativa internet rede - Administrativa       #"
    echo "# --disable-net-adm - Desativa internet rede - Administrativa   #"
    echo "#---------------------------------------------------------------#"
    echo "# --help - Mostra opções                                        #"
    echo "                                                                #"
    echo "#################################################################"
  ;;
  *)
    clear
    echo "Erro, use $0 [start | stop | restart | help]";	
    exit 1
  ;;
esac
exit 0  


