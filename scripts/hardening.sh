#!/bin/bash

echo "script started"
RED=$'\e[31m'
GREEN=$'\e[32m'
YELLOW=$'\e[93m'
BLUE=$'\e[34m'
RESET=$'\e[0m'
# Icons
STEP="${YELLOW}[+]${RESET}"
TIP="${GREEN}[!]${RESET}"
CONCLUSION="${RED}[#]${RESET}"
endc=$'\e[0m' #endc for end-color

STEP_TEXT=(
    "Verify if it's a correct ubuntu version"
    "Creating new user"
    "Creating SSH Key for new user"
    "Securing 'authorized_keys' file"
    "Enabling SSH-only login"
    "Reset sources.list to defaults"
    "Installing required softwares"
    "Configure UFW"
    "Configure Fail2Ban"
    "Changing root password"
    "Scheduling daily update download"
)

echo "List of steps that this script do : "
for step in "${STEP_TEXT[@]}"; do
    echo "${step}"
done

# Check supported OSes
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VER=$VERSION_ID
    CODE_NAME=$VERSION_CODENAME
else
    echo "not supported"
    os_not_supported
    exit 1
fi

echo "os seem supported"

case "$OS" in
debian)
    # If the versions are not 9, 10, 11
    # warn user and ask them to proceed with caution
    DEB_VER_STR=$CODE_NAME
    if ((VER >= 9 && VER <= 11)); then
        new_os_version_warning
    fi
    ;;
ubuntu)
    # If the versions are not 16.04, 18.04, 18.10, 20.04. 21.04
    # warn user and ask them to proceed with caution
    UBT_VER_STR=$CODE_NAME
    if [[ "$VER" != "16.04" ]] && [[ "$VER" != "18.04" ]] && [[ "$VER" != "18.10" ]] && [[ "$VER" != "20.04" ]] && [[ "$VER" != "21.04" ]]; then
        echo "new_os_version_warning "${OS}" "${VER}""
    fi
    ;;
*)
    os_not_supported
    exit 1
    ;;
esac

apt update
apt upgrade
apt dist-upgrade

# Check if UFW is installed
ufw status 2>>/dev/null >&2
if [[ "$?" -eq 1 ]]; then
    echo "Skipping UFW config as it does not seem to be installed - check log to know more"
else
    apt install ufw
    "${STEP}" ufw added
fi

sys_upgrades() {
    apt-get --yes --force-yes update
    apt-get --yes --force-yes upgrade
    apt-get --yes --force-yes autoremove
    apt-get --yes --force-yes autoclean
}

unattended_upg() {
    # IMPORTANT - Unattended upgrades may cause issues
    # But it is known that the benefits are far more than
    # downsides
    apt-get --yes --force-yes install unattended-upgrades
    dpkg-reconfigure -plow unattended-upgrades
    # This will create the file /etc/apt/apt.conf.d/20auto-upgrades
    # with the following contents:
    #############
    # APT::Periodic::Update-Package-Lists "1";
    # APT::Periodic::Unattended-Upgrade "1";
    #############
}

disable_root() {
    passwd -l root
    # for any reason if you need to re-enable it:
    # sudo passwd -l root
}

purge_telnet() {
    # Unless you need to specifically work with telnet, purge it
    # less layers = more sec
    apt-get --yes purge telnet
}

purge_nfs() {
    # This the standard network file sharing for Unix/Linux/BSD     # Unless you require to share data in this manner,
    # less layers = more sec
    apt-get --yes purge nfs-kernel-server nfs-common portmap rpcbind autofs
}

purge_whoopsie() { # disable telemetry - less layers to add more security     # Although whoopsie is useful(a crash log sender to ubuntu)
    # less layers = more sec
    apt-get --yes purge whoopsie
}

set_chkrootkit() {
    apt-get --yes install chkrootkit
    chkrootkit
}

disable_compilers() {
    chmod 000 /usr/bin/byacc
    chmod 000 /usr/bin/yacc
    chmod 000 /usr/bin/bcc
    chmod 000 /usr/bin/kgcc
    chmod 000 /usr/bin/cc
    chmod 000 /usr/bin/gcc
    chmod 000 /usr/bin/*c++
    chmod 000 /usr/bin/*g++
    # 755 to bring them back online
    # It is better to restrict access to them
    # unless you are working with a specific one
}

# Verify what port allow and disallow, can be improved
# firewall() {
#     ufw allow ssh
#     ufw allow http
#     ufw deny 23
#     ufw default deny
#     ufw enable
# }

### Verify if using ssh or openssh
# harden_ssh_brute() {
#     # Many attackers will try to use your SSH server to brute-force passwords.
#     # This will only allow 6 connections every 30 seconds from the same IP address.
#     ufw limit OpenSSH
# }

harden_ssh() {
    sudo sh -c 'echo "PermitRootLogin no" >> /etc/ssh/ssh_config'
}

logwatch_reporter() {
    apt-get --yes --force-yes install logwatch
    # make it run weekly
    cd /
    mv /etc/cron.daily/00logwatch /etc/cron.weekly/
    cd
}

purge_atd() {
    apt-get --yes purge at
    # less layers equals more security
}

disable_avahi() {
    # The Avahi daemon provides mDNS/DNS-SD discovery support
    # (Bonjour/Zeroconf) allowing applications to discover services on the network.
    update-rc.d avahi-daemon disable
}

process_accounting() {
    # Linux process accounting keeps track of all sorts of details about which commands have been run on the server, who ran them, when, etc.
    apt-get --yes --force-yes install acct
    cd /
    touch /var/log/wtmp
    cd
    # To show users' connect times, run ac. To show information about commands previously run by users, run sa. To see the last commands run, run lastcomm.
}


#### Verify what do that part in details 
# kernel_tuning() {
#     sysctl kernel.randomize_va_space=1

#     # Enable IP spoofing protection
#     sysctl net.ipv4.conf.all.rp_filter=1

#     # Disable IP source routing
#     sysctl net.ipv4.conf.all.accept_source_route=0

#     # Ignoring broadcasts request
#     sysctl net.ipv4.icmp_echo_ignore_broadcasts=1

#     # Make sure spoofed packets get logged
#     sysctl net.ipv4.conf.all.log_martians=1
#     sysctl net.ipv4.conf.default.log_martians=1

#     # Disable ICMP routing redirects
#     sysctl -w net.ipv4.conf.all.accept_redirects=0
#     sysctl -w net.ipv6.conf.all.accept_redirects=0
#     sysctl -w net.ipv4.conf.all.send_redirects=0

#     # Disables the magic-sysrq key
#     sysctl kernel.sysrq=0

#     # Turn off the tcp_timestamps
#     sysctl net.ipv4.tcp_timestamps=0

#     # Enable TCP SYN Cookie Protection
#     sysctl net.ipv4.tcp_syncookies=1

#     # Enable bad error message Protection
#     sysctl net.ipv4.icmp_ignore_bogus_error_responses=1

#     # RELOAD WITH NEW SETTINGS
#     sysctl -p
# }

##############

# new_port=2269

# port modification
#nano /etc/ssh/sshd_config
### modification in this line to modify port
#service ssh restart
#echo "Test that ssh connexion stil work with the new port : "${new_port}""

##### firewall implementation
#sudo apt install fail2ban
#sudo nano /etc/fail2ban/jail.local

#### Adapt  [ssh-ddos] part to "enabled = true"
#/etc/init.d/fail2ban restart

main() {
    sys_upgrades
    unattended_upg
    disable_root
    purge_telnet
    purge_nfs
    purge_whoopsie
    set_chkrootkit
    disable_compilers
    firewall
    harden_ssh_brute
    harden_ssh
    logwatch_reporter
    process_accounting
    purge_atd
    disable_avahi
    # kernel_tuning
}

main "$@"
