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
        echo "new_os_version_warning. ⚠️ Think install the new version "${OS}" "${VER}""
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
    apt-get install apt-listchanges -y # apt-listchanges  is  a  tool  to  show  what has been changed in a new version of a Debian package, as compared to the version currently installed on the system. It  does  this  by  extracting  the  relevant  entries  from  both  the  NEWS.Debian   and changelog[.Debian]  files,  usually  found  in /usr/share/doc/package, from Debian package archives.


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



### Verify if using ssh or openssh
harden_ssh_brute() {
    # Many attackers will try to use your SSH server to brute-force passwords.
    # This will only allow 6 connections every 30 seconds from the same IP address.
    ufw limit OpenSSH
}





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
    # Avahi Server is a system that facilitates service discovery on a local network via the mDNS/DNS-SD protocol suite. 
    # It is a free zeroconf implementation that allows programs to discover and publish services or hosts running on a local network with no specific config.
    # The Avahi daemon provides mDNS/DNS-SD discovery supportdaemon 
    # (Bonjour/Zeroconf) allowing applications to discover services on the network.
    # "Every computer that has avahi-daemon (or mdnsresponder) installed will identify itself on the network as 'hostname.local'. For example, my computer 'flute' identifies itself as 'flute.local'."
    update-rc.d avahi-daemon disable
    systemctl stop avahi-daaemon.service
    systemctl stop avahi-daemon.socket
    apt purge avahi-daemon
    echo "avahi disabled" 
}


# Common Unix Print System (CUPS) : this enables a system to function as a print server
disable_cups() {
    apt purge cups
}


# Lightweight Directory Access Protocol (LDAP) Server
# is an open and cross platform software protocol that is used for directory services authentication.

slap_disable() {
    if dpkg -l | grep -qw slapd; then
        echo "slapd is installed. Proceeding with removal."
        # Using apt-get purge to remove slapd and its configuration files
        sudo apt-get purge -y slapd
        echo "slapd has been removed successfully."
    else
        echo "slapd is not installed. No action needed."
    fi

    if ps aux | grep nfsd; then
    echo "NSF is installed in the computer"
    apt-get purge -y rpcbind
    fi
}

nfs_disable() {
    if ps aux | grep nfs-kernel-server; then
    echo "NFS is installed in the machine"
    apt-get purge -y rpcbind
    else 
    echo "NFS is not installed. No action needed."
    fi
}







process_accounting() {
    # Linux process accounting keeps track of all sorts of details about which commands have been run on the server, who ran them, when, etc.
    apt-get --yes --force-yes install acct
    cd /
    touch /var/log/wtmp
    cd
    echo "Users connect times :"
    ac
    echo "Information about commands previously run by users : "
    sa
    echo "Last command run by user : "
    lastcomm
    # To show users' connect times, run ac. To show information about commands previously run by users, run sa. To see the last commands run, run lastcomm.
}


#### Verify what do that part in details 
#### /etc/sysctl.conf file is used to configure kernel parameters at runtime. Linux reads and applies settings from /etc/sysctl.conf at boot time. 
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

#### Verify what do that part in details 
# second_kernel_tunning () {
#     # Turn on execshield
#     kernel.exec-shield=1
#     kernel.randomize_va_space=1
#     # Enable IP spoofing protection
#     net.ipv4.conf.all.rp_filter=1
#     # Disable IP source routing
#     net.ipv4.conf.all.accept_source_route=0
#     # Ignoring broadcasts request
#     net.ipv4.icmp_echo_ignore_broadcasts=1
#     net.ipv4.icmp_ignore_bogus_error_messages=1
#     # Make sure spoofed packets get logged
#     net.ipv4.conf.all.log_martians = 1
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
# firewall_setup() {
#     ufw allow ssh
#     ufw allow http
#     ufw deny 23
#     ufw default deny
#     ufw enable
# }


# List of packages that are considered insecure and should be removed
### List that come from https://freelinuxtutorials.com/top-15-services-to-remove-for-securing-ubuntu-linux/
### Other list 
packages=(
    "xserver-xorg*" # X Windows System this provides the Graphical User Interface or GUI for users to have graphical login access, and interact with a mouse and keyboard. Command to check if X Windows System is installed or not:
    "slapd" 
    "telnet" 
    "telnetd"
    "rsh-server"  
    "slapd"  # Lightweight Directory Access Protocol (LDAP) Server is an open and cross platform software protocol that is used for directory services authentication. Command to check if LDAP  is installed or not:
    "nfs-kernel-server" # Network File System (NFS) -it is a distributed file system protocol that enables user to access remote data and files , retrieval of data from multiple directories and disks across a shared network Command to check if NFS is installed or not:
    "vsftpd" #    File Transfer Protocol (FTP) Server is a network protocol for transferring of files between computers Command to check if FTP is installed or not: (default installed is the VSFTP)
    "samba" # . Samba Server it allows system admin to share file systems and directory with Windows desktops, via the Server Message Block (SMB) protocol
    "nis" #  Network Information Service (NIS) is a client-server directory service protocol used for distributing system configuration files. It is formally known as Yellow Pages.
    "squid" # HTTP Proxy Server it is a server application that acts as an intermediary for clients requests seeking resources from servers. It can cache data to speed up common HTTP requests. The standard proxy server used in many distributions is the “Squid”.
    "snmpd" #  SNMP is a network-management protocol that is used to monitor network devices, collect statistics and performance.
)
# Check also for the following below :
# xinetd nis yp-tools tftpd atftpd tftpd-hpa  rsh-redone-server

purge_useless_packages() {
    for appli in "${packages[@]}"; do
        if ps aux | grep -v grep | grep -w "${appli}" > /dev/null; then
            echo "Using ps: $appli is Running"
            sudo apt-get purge -y "$appli"
        else
            echo "Using ps: $appli is Not running"
        fi
    done
}


# AppArmor ("Application Armor") is a Linux kernel security module that allows the system administrator to restrict programs' capabilities with per-program profiles.
# Check if apparmor is installed command is available
check_apparmor() {
    if command -v apparmor_status >/dev/null 2>&1; then
        echo "AppArmor is installed."
        # Execute apparmor_status with sudo and pipe to grep to check for active profiles
        if apparmor_status | grep -q "profiles are loaded."; then
            echo "AppArmor is active."
        else
            echo "AppArmor is installed but not active or not functioning correctly."
        fi
    else
        echo "AppArmor is not installed."
    fi
}

# Security-Enhanced Linux (SELinux) is a Linux kernel security module that provides a mechanism for supporting access control security policies, including mandatory access controls (MAC). 
# The NSA Security-enhanced Linux Team describes NSA SELinux as[5] a set of patches to the Linux kernel and utilities to provide a strong, flexible, mandatory access control (MAC) architecture into the major subsystems of the kernel. 
# Function to check if SELinux is installed
check_selinux() {
    if command -v getenforce >/dev/null 2>&1; then
        echo "SELinux is installed."
        # Check if SELinux is enforcing, permissive, or disabled
        echo "SELinux status: $(getenforce)"
    else
        echo "SELinux is not installed."
    fi
}

# Perform the checks
check_apparmor
check_selinux






main() {
    sys_upgrades
    unattended_upg
    disable_root
    purge_telnet
    purge_nfs
    purge_whoopsie
    set_chkrootkit
    harden_ssh_brute
    harden_ssh
    logwatch_reporter
    process_accounting
    purge_atd
    disable_avahi
    disable_cups
    disable_compilers
    firewall_setup
    # kernel_tuning

    # Created by me, need to verify if to preserver or not
    slap_disable
    nfs_disable
}

main "$@"

purge_useless_packages