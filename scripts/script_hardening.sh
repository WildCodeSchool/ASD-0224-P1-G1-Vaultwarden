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

echo "The virtualization platform used is : "
systemd-detect-virt

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


# Disable X11 Forwarding in SSH
disable_x11_forwarding() {
    # Ensure the script is run as root
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root" 1>&2
        exit 1
    fi

    # Path to the SSHD configuration file
    SSHD_CONFIG="/etc/ssh/sshd_config"  

    if grep -q "^X11Forwarding no" "$SSHD_CONFIG"; then
        echo "X11 forwarding is already disabled."
    else
        # Backup the original config file
        cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak"

        # Set X11Forwarding to no
        sed -i 's/^X11Forwarding yes/X11Forwarding no/' "$SSHD_CONFIG"

        # Check if X11Forwarding line exists and has been changed, if not, add it
        if ! grep -q "^X11Forwarding no" "$SSHD_CONFIG"; then
            echo "X11Forwarding no" >> "$SSHD_CONFIG"
        fi

        systemctl restart sshd

        echo "X11 forwarding has been disabled."
    fi
}


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
    disable_x11_forwarding
    # kernel_tuning

    # Created by me, need to verify if to preserver or not
    slap_disable
    nfs_disable
}

main "$@"

purge_useless_packages


##### Add later with adaptation the code below,  



# PermitTunnel no
# # Signification : Le paramètre PermitTunnel dans la configuration d'OpenSSH contrôle la possibilité d'établir des tunnels de données SSH. Lorsque cette fonction est activée, les utilisateurs peuvent créer des tunnels qui encapsulent d'autres types de trafic (comme le trafic TCP/IP) dans une connexion SSH.
# # Configuration recommandée : Bien que les tunnels SSH puissent être utiles pour sécuriser le trafic entre des points distants, ils peuvent également être utilisés de manière inappropriée pour contourner les politiques de sécurité réseau. Par exemple, un utilisateur pourrait établir un tunnel SSH pour contourner un pare-feu ou un filtre de contenu. Si les tunnels SSH ne sont pas nécessaires pour vos opérations normales, il est recommandé de désactiver cette fonctionnalité pour réduire la surface d'attaque potentielle. Configurez PermitTunnel no dans votre fichier de configuration SSH pour désactiver la création de tunnels.


# MaxAuthTries
# # Signification : Définit le nombre maximum de tentatives d'authentification autorisées par connexion.
# # Configuration recommandée : Un nombre réduit de tentatives, comme MaxAuthTries 3, aide à prévenir les attaques par force brute.

# ClientAliveInterval et ClientAliveCountMax
# Usage : Ces paramètres aident à détecter les connexions SSH inactives et à les fermer.
# Configuration recommandée : ClientAliveInterval 0 et ClientAliveCountMax 2. Cela ferme la connexion si le client reste inactif pendant 15 minutes.


# AllowUsers et AllowGroups
# Usage : Restreint l'accès SSH à certains utilisateurs ou groupes.
# Configuration recommandée : Utilisez AllowUsers user1 user2 et/ou AllowGroups group1 group2 pour limiter l'accès aux utilisateurs ou groupes spécifiés.

# UsePAM
# Signification : Active ou désactive l'utilisation des Pluggable Authentication Modules (PAM).
# Configuration recommandée : La configuration de UsePAM yes peut être appropriée pour des environnements où les fonctionnalités spécifiques de PAM sont souhaitées.

# DenyUsers et DenyGroups
# Usage : Spécifie les utilisateurs et groupes qui sont explicitement interdits de se connecter via SSH.
# Configuration recommandée : DenyUsers user3 user4 et/ou DenyGroups group3 group4 pour bloquer l'accès à des utilisateurs ou groupes spécifiques.

# Récapitulatif des valeurs recommandées

# Plus simple à reprendre, je vous propose un tableau des valeurs recommandées :
# Paramètre	Valeur recommandée
# Protocol	2
# LogLevel	VERBOSE
# PermitRootLogin	no
# PasswordAuthentication	no
# ChallengeResponseAuthentication	no
# AllowAgentForwarding	no
# PermitTunnel	no
# X11Forwarding	no
# MaxAuthTries	3
# UsePAM	yes
# ClientAliveInterval	0
# ClientAliveCountMax	2
# LoginGraceTime	300


# #!/bin/bash
# # Script to harden ssh on ubuntu/debian server
# # follow on my blog http://www.coderew.com/hardening_ssh_on_remote_ubuntu_debian_server/ 
# # checkout the repo for more scripts https://github.com/nvnmo/handy-scripts

# read -p "Enter your server IP:" serverIP # prompt for server IP
# read -p "Enter your username(requires root privileges):" username # prompt for username
# printf "\nChanging the default SSH port is one of the easiest\n things you can do to help harden you servers security. \nIt will protect you from robots that are programmed \nto scan for port 22 openings, and commence \ntheir attack."
# printf "\n"
# read -p "Do you want to change default SSH port?[Y/n]" -n 1 portChange
# printf "\n"
# portNum=0
# if [[ $portChange =~ ^[Yy]$ ]];then
#   printf "Choose an available port.The port number does not \nreally matter as long as you do no choose something that \nis already in use and falls within the \nport number range."
#   printf "\n"
#   read -p "Port Number:" portNum # a port num to change
#   printf "\n"
# fi
# printf "\n"
# read -p "Do you want to disable root login?[Y/n]" -n 1 rootLogin;printf "\n"
# read -p "Do you want to change protocol version to 2?[Y/n]" -n 1 protocolChange;printf "\n"
# read -p "Do you want to enable privilege seperation?[Y/n]" -n 1 privilegeSep;printf "\n"
# read -p "Do you want to disable empty passwords?[Y/n]" -n 1 emptyPass;printf "\n"
# read -p "Do you want to disable X11 forwarding?[Y/n]" -n 1 x11Forwarding;printf "\n"
# read -p "Do you want to enable TCPKeepAlive to avoid zombies?[Y/n]" -n 1 zombies;printf "\n"


# echo "cat /etc/ssh/sshd_config > /etc/ssh/sshd_config.bak" > .local_script_$0

# if [[ $portChange =~ ^[Yy]$ ]];then
#   echo "sed \"s/.*Port.*/Port $portNum/\" /etc/ssh/sshd_config > temp" >> .local_script_$0
#   echo "cp temp /etc/ssh/sshd_config" >> .local_script_$0
# fi
# if [[ $rootLogin =~ ^[Yy]$ ]];then
#   echo "sed '0,/^.*PermitRootLogin.*$/s//PermitRootLogin no/' /etc/ssh/sshd_config" >> .local_script_$0

# fi
# if [[ $protocolChange =~ ^[Yy]$ ]];then
#   echo "sed -i \"s/^.*Protocol.*$/Protocol 2/\" /etc/ssh/sshd_config" >> .local_script_$0

# fi
# if [[ $privilegeSep =~ ^[Yy]$ ]];then
#   echo "sed -i \"s/^.*UsePrivilegeSeparation.*$/UsePrivilegeSeparation yes/\" /etc/ssh/sshd_config" >> .local_script_$0

# fi
# if [[ $emptyPass =~ ^[Yy]$ ]];then
#   echo "sed -i \"s/^.*PermitEmptyPasswords.*$/PermitEmptyPasswords no/\" /etc/ssh/sshd_config" >> .local_script_$0

# fi
# if [[ $x11Forwarding =~ ^[Yy]$ ]];then
#   echo "sed -i \"s/^.*X11Forwarding.*$/X11Forwarding no/\" /etc/ssh/sshd_config" >> .local_script_$0

# fi
# if [[ $zombies =~ ^[Yy]$ ]];then
#   echo "sed -i \"s/^.*TCPKeepAlive.*$/TCPKeepAlive yes/\" /etc/ssh/sshd_config" >> .local_script_$0

# fi

# MYSCRIPT=`base64 -w0 .local_script_$0`
# ssh -t $username@$serverIP "echo $MYSCRIPT | base64 -d | sudo bash"
# rm .local_script_$0
# echo "Success"
# exit





#  FROM AN OTHER GITHUB, need to adapt and remove useless things _____________________ 

#!/bin/bash
# SSH Hardenning Script



# echo "Escalating Privilage..."
# echo "Checking escalation privilage."
# if [ $UID != 0 ]; then
#   echo "Sorry. Only the ROOT user can run this program!"
#   echo "[FAILED]"
#   exit 0
# fi
# echo "[DONE]"
# echo ""


# echo "SSH Policies Hardening..."

# echo " - Backing-up current configuration file."
# cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# echo " - Changing value Protocol to 2."
# if [ $(cat /etc/ssh/sshd_config | grep Protocol | wc -l) -eq 0 ]; then
#   echo "Protocol 2" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#Protocol [a-zA-Z0-9]*/s/#Protocol [a-zA-Z0-9]*/Protocol 2/' /etc/ssh/sshd_config
#   sed -i -e '1,/Protocol [a-zA-Z0-9]*/s/Protocol [a-zA-Z0-9]*/Protocol 2/' /etc/ssh/sshd_config
# fi

# echo " - Changing value PermitUserEnvironment to no."
# if [ $(cat /etc/ssh/sshd_config | grep PermitUserEnvironment | wc -l) -eq 0 ]; then
#   echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#PermitUserEnvironment [a-zA-Z0-9]*/s/#PermitUserEnvironment [a-zA-Z0-9]*/PermitUserEnvironment no/' /etc/ssh/sshd_config
#   sed -i -e '1,/PermitUserEnvironment [a-zA-Z0-9]*/s/PermitUserEnvironment [a-zA-Z0-9]*/PermitUserEnvironment no/' /etc/ssh/sshd_config
# fi

# echo " - Changing value PermitEmptyPasswords to No."
# if [ $(cat /etc/ssh/sshd_config | grep PermitEmptyPasswords | wc -l) -eq 0 ]; then
#   echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#PermitEmptyPasswords [a-zA-Z0-9]*/s/#PermitEmptyPasswords [a-zA-Z0-9]*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
#   sed -i -e '1,/PermitEmptyPasswords [a-zA-Z0-9]*/s/PermitEmptyPasswords [a-zA-Z0-9]*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
# fi

# echo " - Changing value MaxAuthTries to 6."
# if [ $(cat /etc/ssh/sshd_config | grep MaxAuthTries | wc -l) -eq 0 ]; then
#   echo "MaxAuthTries 6" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#MaxAuthTries [a-zA-Z0-9]*/s/#MaxAuthTries [a-zA-Z0-9]*/MaxAuthTries 6/' /etc/ssh/sshd_config
#   sed -i -e '1,/MaxAuthTries [a-zA-Z0-9]*/s/MaxAuthTries [a-zA-Z0-9]*/MaxAuthTries 6/' /etc/ssh/sshd_config
# fi

# echo " - Changing value LoginGraceTime to 2m."
# if [ $(cat /etc/ssh/sshd_config | grep LoginGraceTime | wc -l) -eq 0 ]; then
#   echo "LoginGraceTime 2m" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#LoginGraceTime [a-zA-Z0-9]*/s/#LoginGraceTime [a-zA-Z0-9]*/LoginGraceTime 2m/' /etc/ssh/sshd_config
#   sed -i -e '1,/LoginGraceTime [a-zA-Z0-9]*/s/LoginGraceTime [a-zA-Z0-9]*/LoginGraceTime 2m/' /etc/ssh/sshd_config
# fi

# echo " - Changing value ClientAliveInterval to 2m."
# if [ $(cat /etc/ssh/sshd_config | grep ClientAliveInterval | wc -l) -eq 0 ]; then
#   echo "ClientAliveInterval 2m" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#ClientAliveInterval [a-zA-Z0-9]*/s/#ClientAliveInterval [a-zA-Z0-9]*/ClientAliveInterval 2m/' /etc/ssh/sshd_config
#   sed -i -e '1,/ClientAliveInterval [a-zA-Z0-9]*/s/ClientAliveInterval [a-zA-Z0-9]*/ClientAliveInterval 2m/' /etc/ssh/sshd_config
# fi

# echo " - Changing value LogLevel to VERBOSE."
# if [ $(cat /etc/ssh/sshd_config | grep LogLevel | wc -l) -eq 0 ]; then
#   echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#LogLevel [a-zA-Z0-9]*/s/#LogLevel [a-zA-Z0-9]*/LogLevel VERBOSE/' /etc/ssh/sshd_config
#   sed -i -e '1,/LogLevel [a-zA-Z0-9]*/s/LogLevel [a-zA-Z0-9]*/LogLevel VERBOSE/' /etc/ssh/sshd_config
# fi

# echo " - Changing value PrintLastLog to yes."
# if [ $(cat /etc/ssh/sshd_config | grep PrintLastLog | wc -l) -eq 0 ]; then
#   echo "PrintLastLog yes" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#PrintLastLog [a-zA-Z0-9]*/s/#PrintLastLog [a-zA-Z0-9]*/PrintLastLog yes/' /etc/ssh/sshd_config
#   sed -i -e '1,/PrintLastLog [a-zA-Z0-9]*/s/PrintLastLog [a-zA-Z0-9]*/PrintLastLog yes/' /etc/ssh/sshd_config
# fi

# echo " - Changing value AllowTcpForwarding to no."
# if [ $(cat /etc/ssh/sshd_config | grep AllowTcpForwarding | wc -l) -eq 0 ]; then
#   echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#AllowTcpForwarding [a-zA-Z0-9]*/s/#AllowTcpForwarding [a-zA-Z0-9]*/AllowTcpForwarding no/' /etc/ssh/sshd_config
#   sed -i -e '1,/AllowTcpForwarding [a-zA-Z0-9]*/s/AllowTcpForwarding [a-zA-Z0-9]*/AllowTcpForwarding no/' /etc/ssh/sshd_config
# fi

# echo " - Changing value X11Forwarding to no."
# if [ $(cat /etc/ssh/sshd_config | grep X11Forwarding | wc -l) -eq 0 ]; then
#   echo "X11Forwarding no" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#X11Forwarding [a-zA-Z0-9]*/s/#X11Forwarding [a-zA-Z0-9]*/X11Forwarding no/' /etc/ssh/sshd_config
#   sed -i -e '1,/X11Forwarding [a-zA-Z0-9]*/s/X11Forwarding [a-zA-Z0-9]*/X11Forwarding no/' /etc/ssh/sshd_config
# fi

# echo " - Changing SSH Daemon Configuraion File Permissions."
# chmod 600 /etc/ssh/sshd_config

# echo " - Restarting SSH Daemon."
# systemctl restart sshd

# echo "[DONE]"
# exit 0

# echo "Checking escalation privilage."
# if [ $UID != 0 ]; then
#   echo "Sorry. Only the ROOT user can run this program!"
#   echo "[FAILED]"
#   exit 0
# fi
# echo "[DONE]"
# echo ""


# echo "SSH Policies Hardening..."

# echo " - Backing-up current configuration file."
# cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# echo " - Changing value Protocol to 2."
# if [ $(cat /etc/ssh/sshd_config | grep Protocol | wc -l) -eq 0 ]; then
#   echo "Protocol 2" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#Protocol [a-zA-Z0-9]*/s/#Protocol [a-zA-Z0-9]*/Protocol 2/' /etc/ssh/sshd_config
#   sed -i -e '1,/Protocol [a-zA-Z0-9]*/s/Protocol [a-zA-Z0-9]*/Protocol 2/' /etc/ssh/sshd_config
# fi

# echo " - Changing value PermitUserEnvironment to no."
# if [ $(cat /etc/ssh/sshd_config | grep PermitUserEnvironment | wc -l) -eq 0 ]; then
#   echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#PermitUserEnvironment [a-zA-Z0-9]*/s/#PermitUserEnvironment [a-zA-Z0-9]*/PermitUserEnvironment no/' /etc/ssh/sshd_config
#   sed -i -e '1,/PermitUserEnvironment [a-zA-Z0-9]*/s/PermitUserEnvironment [a-zA-Z0-9]*/PermitUserEnvironment no/' /etc/ssh/sshd_config
# fi

# echo " - Changing value PermitEmptyPasswords to No."
# if [ $(cat /etc/ssh/sshd_config | grep PermitEmptyPasswords | wc -l) -eq 0 ]; then
#   echo "PermitEmptyPasswords no" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#PermitEmptyPasswords [a-zA-Z0-9]*/s/#PermitEmptyPasswords [a-zA-Z0-9]*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
#   sed -i -e '1,/PermitEmptyPasswords [a-zA-Z0-9]*/s/PermitEmptyPasswords [a-zA-Z0-9]*/PermitEmptyPasswords no/' /etc/ssh/sshd_config
# fi

# echo " - Changing value MaxAuthTries to 6."
# if [ $(cat /etc/ssh/sshd_config | grep MaxAuthTries | wc -l) -eq 0 ]; then
#   echo "MaxAuthTries 6" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#MaxAuthTries [a-zA-Z0-9]*/s/#MaxAuthTries [a-zA-Z0-9]*/MaxAuthTries 6/' /etc/ssh/sshd_config
#   sed -i -e '1,/MaxAuthTries [a-zA-Z0-9]*/s/MaxAuthTries [a-zA-Z0-9]*/MaxAuthTries 6/' /etc/ssh/sshd_config
# fi

# echo " - Changing value LoginGraceTime to 2m."
# if [ $(cat /etc/ssh/sshd_config | grep LoginGraceTime | wc -l) -eq 0 ]; then
#   echo "LoginGraceTime 2m" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#LoginGraceTime [a-zA-Z0-9]*/s/#LoginGraceTime [a-zA-Z0-9]*/LoginGraceTime 2m/' /etc/ssh/sshd_config
#   sed -i -e '1,/LoginGraceTime [a-zA-Z0-9]*/s/LoginGraceTime [a-zA-Z0-9]*/LoginGraceTime 2m/' /etc/ssh/sshd_config
# fi

# echo " - Changing value ClientAliveInterval to 2m."
# if [ $(cat /etc/ssh/sshd_config | grep ClientAliveInterval | wc -l) -eq 0 ]; then
#   echo "ClientAliveInterval 2m" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#ClientAliveInterval [a-zA-Z0-9]*/s/#ClientAliveInterval [a-zA-Z0-9]*/ClientAliveInterval 2m/' /etc/ssh/sshd_config
#   sed -i -e '1,/ClientAliveInterval [a-zA-Z0-9]*/s/ClientAliveInterval [a-zA-Z0-9]*/ClientAliveInterval 2m/' /etc/ssh/sshd_config
# fi

# echo " - Changing value LogLevel to VERBOSE."
# if [ $(cat /etc/ssh/sshd_config | grep LogLevel | wc -l) -eq 0 ]; then
#   echo "LogLevel VERBOSE" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#LogLevel [a-zA-Z0-9]*/s/#LogLevel [a-zA-Z0-9]*/LogLevel VERBOSE/' /etc/ssh/sshd_config
#   sed -i -e '1,/LogLevel [a-zA-Z0-9]*/s/LogLevel [a-zA-Z0-9]*/LogLevel VERBOSE/' /etc/ssh/sshd_config
# fi

# echo " - Changing value PrintLastLog to yes."
# if [ $(cat /etc/ssh/sshd_config | grep PrintLastLog | wc -l) -eq 0 ]; then
#   echo "PrintLastLog yes" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#PrintLastLog [a-zA-Z0-9]*/s/#PrintLastLog [a-zA-Z0-9]*/PrintLastLog yes/' /etc/ssh/sshd_config
#   sed -i -e '1,/PrintLastLog [a-zA-Z0-9]*/s/PrintLastLog [a-zA-Z0-9]*/PrintLastLog yes/' /etc/ssh/sshd_config
# fi

# echo " - Changing value AllowTcpForwarding to no."
# if [ $(cat /etc/ssh/sshd_config | grep AllowTcpForwarding | wc -l) -eq 0 ]; then
#   echo "AllowTcpForwarding no" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#AllowTcpForwarding [a-zA-Z0-9]*/s/#AllowTcpForwarding [a-zA-Z0-9]*/AllowTcpForwarding no/' /etc/ssh/sshd_config
#   sed -i -e '1,/AllowTcpForwarding [a-zA-Z0-9]*/s/AllowTcpForwarding [a-zA-Z0-9]*/AllowTcpForwarding no/' /etc/ssh/sshd_config
# fi

# echo " - Changing value X11Forwarding to no."
# if [ $(cat /etc/ssh/sshd_config | grep X11Forwarding | wc -l) -eq 0 ]; then
#   echo "X11Forwarding no" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#X11Forwarding [a-zA-Z0-9]*/s/#X11Forwarding [a-zA-Z0-9]*/X11Forwarding no/' /etc/ssh/sshd_config
#   sed -i -e '1,/X11Forwarding [a-zA-Z0-9]*/s/X11Forwarding [a-zA-Z0-9]*/X11Forwarding no/' /etc/ssh/sshd_config
# fi

# echo " - Changing SSH Daemon Configuraion File Permissions."
# chmod 600 /etc/ssh/sshd_config

# echo " - Restarting SSH Daemon."
# systemctl restart sshd

# echo "[DONE]"
# exit 0
