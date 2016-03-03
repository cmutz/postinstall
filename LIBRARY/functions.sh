println() {
    level=$1
    text=$2

    if [ "$level" == "error" ]; then
        echo -en "\033[0;36;31m$text\033[0;38;39m\n\r"
    elif [ "$level" == "warn" ]; then
        echo -en "\033[0;36;33m$text\033[0;38;39m\n\r"
    else
        echo -en "\033[0;36;40m$text\033[0;38;39m\n\r"
    fi
}

ask_yn_question() {
    QUESTION=$1

    while true;
    do 
        echo -en "${QUESTION} (y/n) "
        read REPLY
        if [ "${REPLY}" == "y" ];
        then
            return 0;
        fi
        if [ "${REPLY}" == "n" ];
        then
            return 1;
        fi
    echo "Don't tell you life, reply using 'y' or 'n'"'!'
    done
}

# function dectection de distribution 
detectdistro () {
  if [[ -z $distro ]]; then
    distro="Unknown"
    if grep -i debian /etc/lsb-release >/dev/null 2>&1; then distro="debian"; fi
    if [ -f /etc/debian_version ]; then distro="debian"; fi
    if grep -i ubuntu /etc/lsb-release >/dev/null 2>&1; then distro="ubuntu"; fi
    if grep -i mint /etc/lsb-release >/dev/null 2>&1; then distro="linux Mint"; fi
    if [ -f /etc/arch-release ]; then distro="arch Linux"; fi
    if [ -f /etc/fedora-release ]; then distro="fedora"; fi
    if [ -f /etc/redhat-release ]; then distro="red Hat Linux"; fi
    if [ -f /etc/slackware-version ]; then distro="Slackware"; fi
    if [ -f /etc/SUSE-release ]; then distro="SUSE"; fi
    if [ -f /etc/mandrake-release ]; then distro="Mandrake"; fi
    if [ -f /etc/mandriva-release ]; then distro="Mandriva"; fi
    if [ -f /etc/crunchbang-lsb-release ]; then distro="Crunchbang"; fi
    if [ -f /etc/gentoo-release ]; then distro="Gentoo"; fi
    if [ -f /var/run/dmesg.boot ] && grep -i bsd /var/run/dmesg.boot; then distro="BSD"; fi
    if [ -f /usr/share/doc/tc/release.txt ]; then distro="Tiny Core"; fi
  fi
}

#LOG functions
f_LOG() {
    echo "`date`:$@" >> $LOGFILE
}

f_INFO() {
    echo "$@"
    f_LOG "INFO: $@"
}

f_WARNING() {
    echo "$@"
    f_LOG "WARNING: $@"
}

