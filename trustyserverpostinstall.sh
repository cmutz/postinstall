#!/bin/bash
# Mon script de post installation serveur Ubuntu 14.04 Trusty
# creation : 11-02-2014
# Origine Mutz Clément <c.mutz@whoople.fr>
# Pour une utilisation par Whoople
# GPL
#
# Syntaxe: # su - -c "./preciseserverpostinstall.sh"
# Syntaxe: or # sudo ./preciseserverpostinstall.sh

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
	rkhunter chkrootkit fail2ban \
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
if [[ "$distro" != "ubuntu" ]]; then
println error "le script doit être lancé sur machine ubuntu"
  exit 1
fi

# Test que le script est lance sur une debian wheezy
## Installation du pre requis pour le test de version
#apt-get -y install bc
pre=`lsb_release -c | awk '{ print $2 }'`
if [[ "$pre" != "trusty"  ]]; then
println error "le script doit être lancé sur machine ubuntu Precise (14.04)"
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
apt-get dist-upgrade

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
export LANGUAGE=fr_FR.UTF-8
export LANG=fr_FR.UTF-8
export LC_ALL=fr_FR.UTF-8
locale-gen fr_FR.UTF-8
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
sed -i 's/bantime  = 600/bantime  = 3600/g' /etc/fail2ban/jail.conf




#################################################################
#	5./ Configuration de logwatch				#
#################################################################
println warn "#################################################################"
println warn "#	5./ Configuration de logwatch 				      #\n"
println warn "#################################################################\n"
cp /usr/share/logwatch/default.conf/logwatch.conf /etc/logwatch/conf/logwatch.conf
#sed -i 's/logwatch --output mail/logwatch --output mail --mailto '$MAIL' --detail high/g' /etc/cron.daily/00logwatch
sed -i 's/\/usr\/sbin\/logwatch --output --detail high/\/usr\/sbin\/logwatch --outputmail --mailto '$MAIL'  --detail high/g' /etc/cron.daily/00logwatch
sed -i 's/Format = text/Format = html/g' /etc/logwatch/conf/logwatch.conf

logwatch --mailto $MAIL

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

