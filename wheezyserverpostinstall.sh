#!/bin/bash
# Mon script de post installation serveur Debian 7.0 aka Wheezy
#
# Origine : Nicolargo - 05/2013
# Modifié par Mutz Clément <c.mutz@whoople.fr>
# Adapaté pour une utilisation par Trust
# GPL
#
# Syntaxe: # su - -c "./wheezyserverpostinstall.sh"
# Syntaxe: or # sudo ./wheezyserverpostinstall.sh
VERSION="1.1"

# Insertion de la LIBRARY
. ./LIBRARY/functions.sh

#=============================================================================
# Liste des applications à installer: A adapter a vos besoins
# Voir plus bas les applications necessitant un depot specifique
# Securite
LISTE="	logwatch bash-static 		\
	busybox-static e2fsck-static binutils 	\
	make patch tcpdump tshark rsyslog atop 	\
	htop iftop iotop ipmitool iptraf itop 	\
	lm-sensors mytop mailutils postfix 	\
	telnet vlan w3m cifs-utils bzip2 p7zip 	\
	unrar-free unzip apt-file 		\
	bash-completion bc gawk kpartx less 	\
	lsb-release openssh-server mbr minicom 	\
	mlocate mmv molly-guard ncurses-hexedit \
	psmisc pwgen screen time vim tmux tree 	\
	rkhunter chkrootkit portsentry fail2ban \
	lynis ntp locales"
#=============================================================================

# Si 0 alors le script stop après la configuration des locales
CONFIGURATION=1

# Test que le script est lance en root
if [ $EUID -ne 0 ]; then
println error "Le script doit être lancé en root: # sudo $0" 1>&2
  exit 1
fi

# Test que le script est lance sur une debian
detectdistro
if [[ "$distro" != "debian" ]]; then
println error "le script doit être lancé sur machine debian"
  exit 1
fi

# Test que le script est lance sur une debian wheezy
## Installation du pre requis pour le test de version
apt-get -y install bc
wh=`cat /etc/debian_version`
if [ $(bc -l <<<"$wh > 7.0") -eq 0 ]; then
println error "le script doit être lancé sur machine debian WHEEZY"
  exit 1
fi


#################################################################
#	1./ Mise à jour de la machine				#
#################################################################
println warn "#################################################################"
println warn "#	1./ Mise à jour de la machine	              	 	      #\n"
println warn "#################################################################\n"
println warn "Mise a jour de la liste des depots"
apt-get update

println warn "Mise a jour du systeme"
apt-get -y upgrade

println warn "Installation des logiciels suivants: $LISTE"
apt-get -y install $LISTE


#################################################################
#	2./ Configuration des locales				#
#################################################################
println warn "#################################################################"
println warn "#	2./ Configuration des locales				      #\n"
println warn "#################################################################\n"
# Pour éviter les messages de Warning de Perl
# Source: http://charles.lescampeurs.org/2009/02/24/debian-lenny-and-perl-locales-warning-messages
dpkg-reconfigure locales


if [[ $CONFIGURATION -eq 0 ]]; then
	echo -e "La mise à niveau de la machine est maintenant termine \n" && exit 0
fi

println warn "\tConfiguration de la machine\n"
#echo -n "Adresse d'écoute de la machine pour le ssh (mettre 0.0.0.0 pour *):"
#read SSH_ADDRESS

#openssh-server addresse d'ecoute
#sed -i 's/#ListenAddress 0.0.0.0/ListenAddress '$SSH_ADDRESS'/g'	/etc/ssh/sshd_config

println warn "Adresse mail pour les rapports de securite: "
read MAIL


#################################################################
#	3./ Configuration de cron-apt				#
#################################################################
#echo -e "#################################################################"
#echo -e	"#	3./ Configuration de cron-apt				 #\n"
#echo -e	"#################################################################\n"
#sed -i 's/# MAILTO="root"/MAILTO="'$MAIL'"/g' /etc/cron-apt/config


#################################################################
#	4./ Configuration de fail2ban				#
#################################################################
println warn "#################################################################"
println warn "#	4./ Configuration de fail2ban				      #\n"
println warn "#################################################################\n"
sed -i 's/destemail = root@localhost/destemail = '$MAIL'/g' /etc/fail2ban/jail.conf


#################################################################
#	5./ Configuration de logwatch				#
#################################################################
println warn "#################################################################"
println warn "#	5./ Configuration de logwatch 				      #\n"
println warn "#################################################################\n"
#sed -i 's/logwatch --output mail/logwatch --output mail --mailto '$MAIL' --detail high/g' /etc/cron.daily/00logwatch
sed -i 's/\/usr\/sbin\/logwatch --output --detail high/\/usr\/sbin\/logwatch --outputmail --mailto '$MAIL'  --detail high/g' /etc/cron.daily/00logwatch


#################################################################
#	6./ Configuration de portsentry				#
#################################################################
println warn "#################################################################"
println warn "#	6./ Configuration de portsentry				      #\n"
println warn "#################################################################\n"
mv /etc/portsentry/portsentry.conf /etc/portsentry/portsentry.conf.back; touch /etc/portsentry/portsentry.conf
cat <<EOF >/etc/portsentry/portsentry.conf
# These port bindings are *ignored* for Advanced Stealth Scan Detection Mode.
# Use these if you just want to be aware:
TCP_PORTS="1,11,15,79,111,119,143,540,635,1080,1524,2000,5742,6667,12345,12346,20034,27665,31337,32771,32772,32773,32774,40421,49724,54320"
UDP_PORTS="1,7,9,69,161,162,513,635,640,641,700,37444,34555,31335,32770,32771,32772,32773,32774,31337,54321"
# By specifying ports here PortSentry will simply not respond to
# incoming requests, in effect PortSentry treats them as if they are
# actual bound daemons. The default ports are ones reported as
# problematic false alarms and should probably be left alone for
# all but the most isolated systems/networks.
ADVANCED_EXCLUDE_TCP="113,139"
ADVANCED_EXCLUDE_UDP="520,138,137,67"
# This file is made from /etc/portsentry/portsentry.ignore.static
IGNORE_FILE="/etc/portsentry/portsentry.ignore"
HISTORY_FILE="/var/lib/portsentry/portsentry.history"
BLOCKED_FILE="/var/lib/portsentry/portsentry.blocked"
RESOLVE_HOST = "0"
BLOCK_UDP="1"
BLOCK_TCP="1"
KILL_ROUTE="/sbin/route add -host $TARGET$ reject && (route -n | grep "-" && echo -e "\n \n IP RESOLU AVEC DIG" && route -n | grep "-" | cut -d " " -f1-1 | nslookup | grep "name =" | cut -d "=" -f2-2 | sort -u) | mutt -s '[ns1] Un scanner a ete bloque' infrastructure@whoople.fr "
KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP && /sbin/iptables -I INPUT -s $TARGET$ -m limit --limit 3/minute --limit-burst 5 -j LOG --log-level DEBUG --log-prefix 'Portsentry: dropping: '"
KILL_HOSTS_DENY="ALL: $TARGET$ : DENY"
SCAN_TRIGGER="0"
#PORT_BANNER="** UNAUTHORIZED ACCESS PROHIBITED *** YOUR CONNECTION ATTEMPT HAS BEEN LOGGED. GO AWAY."
EOF

[[ -e '/etc/default/portsentry' ]] && command sed -i -e 's/^TCP_MODE=.*$/TCP_MODE="atcp"/' '/etc/default/portsentry'
[[ -e '/etc/default/portsentry' ]] && command sed -i -e 's/^UDP_MODE=.*$/UDP_MODE="audp"/' '/etc/default/portsentry'

mv /etc/portsentry/portsentry.ignore.static /etc/portsentry/portsentry.ignore.static.ori; touch /etc/portsentry/portsentry.ignore.static
cat <<EOF >/etc/portsentry/portsentry.ignore.static
# /etc/portsentry/portsentry.ignore.static
#
# Keep 127.0.0.1 and 0.0.0.0 to keep people from playing games.
# Put hosts in here you never want blocked. This includes the IP addresses
# of all local interfaces on the protected host (i.e virtual host, mult-home)
# Keep 127.0.0.1 and 0.0.0.0 to keep people from playing games.
#
# Upon start of portsentry(8) via /etc/init.d/portsentry this file
# will be merged into portsentry.ignore.
#
# PortSentry can support full netmasks for networks as well. Format is:
#
# <IP Address>/<Netmask>
#
# Example:
#
# 192.168.2.0/24
# 192.168.0.0/16
# 192.168.2.1/32
# Etc.
#
# If you don't supply a netmask it is assumed to be 32 bits.
#
#
127.0.0.1/32
0.0.0.0
# Réseau Servitics
10.254.11.0/24
10.254.10.0/24
10.254.20.0/24
10.254.30.0/24
10.254.31.0/24
10.254.32.0/24
10.254.33.0/24
10.254.50.0/24

# Servitics Vlan 60
37.122.200.64/27

# Epiais les louvres
46.254.229.64/30
46.254.229.120/32
46.254.229.121/32
46.254.229.122/32

# Plages d'IP routées sur la Baie Telco Center
46.254.228.232/29

# p.duru
80.14.28.10
83.157.238.108

# c.mutz
88.174.98.97

# c.kassi
88.173.241.180

EOF

/etc/init.d/portsentry restart

##################################################################
#       7./ Configuration de postfix	                         #
##################################################################
println warn "#################################################################"
println warn "#      7./ Configuration de postfix	                      #\n"
println warn "#################################################################\n"

hostname > /etc/mailname

mv /etc/postfix/main.cf /etc/postfix/main.cf.ori; touch /etc/postfix/main.cf

cat <<EOF >/etc/postfix/main.cf
myorigin = /etc/mailname
smtpd_banner = $myhostname ESMTP

biff = no

append_dot_mydomain = no

readme_directory = no

myhostname = applb1
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
mydestination = localhost.localdomain, localhost
relayhost = mail.whoople.fr
mynetworks = 127.0.0.0/8
mailbox_command = procmail -a "$EXTENSION"
mailbox_size_limit = 0
recipient_delimiter = +

default_transport = smtp
relay_transport = smtp

inet_interfaces = all
inet_protocols = ipv4
EOF

/etc/init.d/postfix restart

#################################################################
#       8./ Configuration ntp server                     	#
#################################################################
println warn "#################################################################"
println warn "# 8./ Configuration ntp server		                      #\n"
println warn "#################################################################\n"
mv /etc/ntp.conf /etc/ntp.conf.ori; touch /etc/ntp.conf
cat <<EOF >/etc/ntp.conf
# /etc/ntp.conf, configuration for ntpd; see ntp.conf(5) for help

driftfile /var/lib/ntp/ntp.drift


# Enable this if you want statistics to be logged.
#statsdir /var/log/ntpstats/

statistics loopstats peerstats clockstats
filegen loopstats file loopstats type day enable
filegen peerstats file peerstats type day enable
filegen clockstats file clockstats type day enable


# You do need to talk to an NTP server or two (or three).
#server ntp.your-provider.example

# pool.ntp.org maps to about 1000 low-stratum NTP servers.  Your server will
# pick a different set every time it starts up
Please consider joining the
# pool: <http://www.pool.ntp.org/join.html>
ntp.in.whoople.net iburst
server 0.debian.pool.ntp.org iburst
server 1.debian.pool.ntp.org iburst
server 2.debian.pool.ntp.org iburst
server 3.debian.pool.ntp.org iburst


# Access control configuration; see /usr/share/doc/ntp-doc/html/accopt.html for
# details.  The web page <http://support.ntp.org/bin/view/Support/AccessRestrict
ions>
# might also be helpful.
#
# Note that "restrict" applies to both servers and clients, so a configuration
# that might be intended to block requests from certain clients could also end
# up blocking replies from your own upstream servers.

# By default, exchange time with everybody, but don't allow configuration.
restrict -4 default kod notrap nomodify nopeer noquery
restrict -6 default kod notrap nomodify nopeer noquery
# Local users may interrogate the ntp server more closely
EOF

service ntp restart

ntpq -p

#################################################################
#       9./ Configuration basic iptables                     	#
#################################################################
println warn "#################################################################"
println warn "# 9./ Configuration basic iptables	                      #\n"
println warn "#################################################################\n"
if [ ! -a "/etc/init.d/whoople_firewall" ];then

	touch /etc/init.d/whoople_firewall
	cat <<EOF >/etc/init.d/whoople_firewall
#!/bin/bash
### BEGIN INIT INFO
# Provides:          whoople_firwall
# Required-Start:    $local_fs
# Required-Stop:     $local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: v0.1 - 27/02/2014 - c.mutz <c.mutz@whoople.fr>. minimal firewall
# Description:      
#
### END INIT INFO

. /lib/lsb/init-functions
case "\$1" in
start)  log_daemon_msg "Starting VM with minimal firewall" "whoople_firewall"
    iptables -t filter -F
    iptables -t filter -X
    ## Flood/deny de service
    iptables -A FORWARD -p tcp --syn -m limit --limit 1/second -j ACCEPT
    iptables -A FORWARD -p udp -m limit --limit 1/second -j ACCEPT
    iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/second -j ACCEPT
    # Scan de port
    iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
    ;;

*)      log_action_msg "Usage: /etc/init.d/whoople_firewall start"
        exit 2
        ;;
esac
exit 0        
EOF
	
	chmod +x /etc/init.d/whoople_firewall
	insserv -d -v whoople_firewall
fi

#################################################################
#       10./ Configuration whoople_firstboot                     	#
#################################################################
println warn "#################################################################"
println warn "# 10./ Configuration whoople_firstboot	                      #\n"
println warn "#################################################################\n"
mv /etc/init.d/whoople_firstboot /etc/init.d/whoople_firstboot.ori; touch /etc/init.d/whoople_firstboot
cat <<EOF2 >/etc/init.d/whoople_firstboot
#!/bin/bash
### BEGIN INIT INFO
# Provides:          whoople_firstboot
# Required-Start:    \$local_fs 
# Required-Stop:     \$local_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: v0.1 - 09/02/2012 - r.meillon - Make all tasks needed when the VM boots for the first time.
# Short-Description: v0.2 - 13/05/2014 - c.mutz - add support first configuration network
# Description:       
#
### END INIT INFO

. /lib/lsb/init-functions

case "\$1" in
start)  log_daemon_msg "Starting tasks needed for the first boot" "whoople_firstboot"
                echo
        # Removing old SSH keys if they exists the create new one
                [ -a "/etc/ssh/ssh_host_dsa_key" ] && rm -rf /etc/ssh/ssh_host_dsa_key*
                [ -a "/etc/ssh/ssh_host_rsa_key" ] && rm -rf /etc/ssh/ssh_host_rsa_key*
                /usr/bin/ssh-keygen -t dsa -f /etc/ssh/ssh_host_dsa_key -N ""
                /usr/bin/ssh-keygen -t rsa -f /etc/ssh/ssh_host_rsa_key -N ""

	# wait 5 secondes clean terminal
	sleep 5

        log_daemon_msg " interfaces"
        read INTERFACES
        log_daemon_msg " address ip"
        read ADDRESS
        log_daemon_msg " netmask"
        read NETMASK
        log_daemon_msg " gateway"
        read GATEWAY
        log_daemon_msg " dns server (ex : 8.8.8.8)"
        read DNS

        cat <<EOF >/etc/network/interfaces
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
allow-hotplug \$INTERFACES
auto \$INTERFACES
iface \$INTERFACES inet static
       address \$ADDRESS
       netmask \$NETMASK
       gateway \$GATEWAY

EOF

	service networking restart

	## Modification du nom de la machine
        log_daemon_msg "modification du nom de la machine"
        read NAME

        sed -i.bak "1,2d" /etc/hosts

        cat <<EOF3 >/etc/hosts
127.0.0.1       localhost
\$ADDRESS	\$NAME
           
        
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

EOF3

        cat <<EOF4 >/etc/hostname
\$NAME
EOF4
        cat <<EOF5 >/etc/resolv.conf
nameserver \$DNS

EOF5

	# modification du fichier d'ecoute de sshd
	sed -i.bak "s/^#ListenAddress 0.0.0.0/ListenAddress \$ADDRESS/" /etc/ssh/sshd_config

	service ssh restart

        log_daemon_msg "update machine whoople_fistboot"
        # update/upgrade machine
        /usr/bin/apt-get update
        /usr/bin/apt-get -y upgrade
        /usr/bin/apt-get update
        /usr/bin/apt-get -y dist-upgrade

                # removing this script from the boot process
                insserv -f -r whoople_firstboot
        log_end_msg \$?
        ;;
*)      log_action_msg "Usage: /etc/init.d/whoople_firstboot start"
        exit 2
        ;;
esac

EOF2

        chmod +x /etc/init.d/whoople_firstboot
        insserv -d -v whoople_firstboot

println warn "#################################################################"
println warn "#################################################################"
println warn "#################################################################"
println warn "#################################################################"
println error "		user root changera de mot de passe au permier login	"
println warn "#################################################################"
println warn "#################################################################"
println warn "#################################################################"
println warn "#################################################################"


chage -d 0 root


#################################################################
#       FIN Configuration postinstall	                        #
#################################################################
println warn "#################################################################"
println warn "# FIN Configuration postinstall	                              #\n"
println warn "#################################################################\n"

echo "Autres action à faire si besoin:"
echo "- Securisé le serveur avec un Firewall"
echo " > http://www.debian.org/doc/manuals/securing-debian-howto/ch-sec-services.en.html"
echo " > https://raw.github.com/nicolargo/debianpostinstall/master/firewall.sh"
echo "- Securisé le daemon SSH"
echo " > http://www.debian-administration.org/articles/455"
echo "- Permettre l'envoi de mail"
echo " > http://blog.nicolargo.com/2011/12/debian-et-les-mails-depuis-la-ligne-de-commande.html"


echo -e "La mise à niveau de la machine est maintenant termine \n" && exit 0

