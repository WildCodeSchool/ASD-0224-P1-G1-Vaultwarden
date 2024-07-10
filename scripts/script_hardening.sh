#!/bin/bash
RED=$'\e[31m'
GREEN=$'\e[32m'
YELLOW=$'\e[93m'
BLUE=$'\e[34m'
RESET=$'\e[0m'
# Icons
STEP_ICON="${YELLOW}[+]${RESET}"
TIP="${GREEN}[!]${RESET}"
CONCLUSION="${RED}[#]${RESET}"
endc=$'\e[0m' #endc for end-color

# Define the remote server credentials
SSH_CONFIG="/etc/ssh/ssh_config"  
SSHD_CONFIG="/etc/ssh/sshd_config"  

#### Variable for testing 
REMOTE_USER="root"
EMAIL="root@gmail.com"
REMOTE_HOST="your_remote_host"
REMOTE_PORT="22" # Default SSH port, change if necessary
declare -i PORT=1754
REMOTE_USER="your_remote_username"
REMOTE_HOST="your_remote_host"
REMOTE_PORT="22" # Default SSH port, change if necessary
SSH_KEY="/path/to/your/private/key"
# SSH_declare -i PORT=1754

SSH_PRE_PATH="~/.ssh/id_ed25519"
SSH_KEY_PATH=""${SSH_PRE_PATH}"_"{$SERVER_NAME}""
SSH_KEY_PUB_PATH=""${SSH_PRE_PATH}"_"{$SERVER_NAME}".pub"

#### Variable for production
# read -p "What is your email address ? " EMAIL
# read -p "What is your server name ? " SERVER_NAME
# read -p "Enter the name of your remote server: " SERVER_NAME
# read -p "What is the SSH port number on the remote server? " SSH_PORT

# read -p "What is your remote username? " REMOTE_USER
# read -p "What is the remote host name ? " REMOTE_HOST
# read -p "What is the SSH port number on the remote server ? " REMOTE_PORT
# read -p "What is the SSH port number on the remote server ? " SSH_PORT
# ##  read -p " What is the remote ssh_key path on your local machine ?" SSH_KEY ### Already set with static variable

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


# # REMOTE_COMMANDS=$(cat <<'EOF'
# # Function to set up SSH key-based authentication using Ed25519
# setup_ssh_ed25519() {
#     if [ -z "$$REMOTE_USER" ] || [ -z "$remote_host" ] || [ -z "$email" ]; then
#         echo "Missing required variables: remote_user, remote_host, or email."
#         return 1
#     fi

#     # Generate Ed25519 key
#     ssh-keygen -t ed25519 -C "$EMAIL" -f ~/.ssh/id_ed25519_$SERVER_NAME

#     # Automatically copy the Ed25519 key to the server
#     ssh-copy-id -i $SSH_KEY_PUB_PATH -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST

#     # SSH into the server to harden SSH configuration
#     ssh -i $SSH_KEY -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST <<EOF

#         # Restart SSH service
#         sudo systemctl restart sshd

#         echo "$STEP_ICON SSH configuration restarted."
# EOF

#     cd ~/.ssh
#     sudo ssh-agent bash
#     ssh-add $SSH_KEY_PATH

#     echo "$STEP_ICON SSH key-based authentication setup using $SSH_PRE_PATH is complete."
# }

# Call the function to set up SSH key-based authentication
echo "$STEP_ICON The virtualization platform used is : "
systemd-detect-virt

echo "List of steps that this script do : "
for step in "${STEP_TEXT[@]}"; do
    echo "$STEP_ICON ${step}"
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
apt install openssh-client
apt install openssh-server


sys_upgrades() {
    apt-get --yes --force-yes update
    apt-get --yes --force-yes upgrade
    apt-get --yes --force-yes autoremove
    apt-get --yes --force-yes autoclean
}

unattended_upg() {
    # IMPORTANT - Unattended upgrades may cause issues
    # But it is known that the benefits are far more than downsides
    apt-get --yes --force-yes install unattended-upgrades
    dpkg-reconfigure -plow unattended-upgrades
    apt-get install apt-listchanges -y # apt-listchanges  is  a  tool  to  show  what has been changed in a new version of a Debian package, as compared to the version currently installed on the system. It  does  this  by  extracting  the  relevant  entries  from  both  the  NEWS.Debian   and changelog[.Debian]  files,  usually  found  in /usr/share/doc/package, from Debian package archives.
    echo "$STEP_ICON unattended updates added"
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
    echo "$STEP_ICON root disabled"
}

purge_telnet() {
    # Unless you need to specifically work with telnet, purge it
    # less layers = more sec
    apt-get --yes purge telnet
    echo "$STEP_ICON telnet disabled"
}

purge_nfs() {
    # This the standard network file sharing for Unix/Linux/BSD     # Unless you require to share data in this manner,
    # less layers = more sec
    apt-get --yes purge nfs-kernel-server nfs-common portmap rpcbind autofs
    echo "$STEP_ICON nfs disabled"
}

purge_whoopsie() { # disable telemetry - less layers to add more security     # Although whoopsie is useful(a crash log sender to ubuntu)
    # less layers = more sec
    apt-get --yes purge whoopsie
    echo "$STEP_ICON whoopsie disabled"
}

### Verify if using ssh or openssh
harden_ssh_brute() {
    # Many attackers will try to use your SSH server to brute-force passwords.
    # This will only allow 6 connections every 30 seconds from the same IP address.
    ufw limit OpenSSH
    echo "$STEP_ICON ssh hardening added with rate limiting"
}


logwatch_reporter() {
    apt-get --yes --force-yes install logwatch
    # make it run weekly
    cd /
    mv /etc/cron.daily/00logwatch /etc/cron.weekly/
    cd
    echo "$STEP_ICON logwatch installed with cronjob"
}

purge_atd() {
    apt-get --yes purge at
    echo "$STEP_ICON purge atd"
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
    echo "$STEP_ICON avahi disabled"
}

# Common Unix Print System (CUPS) : this enables a system to function as a print server
disable_cups() {
    apt purge cups
    echo "$STEP_ICON cups disabled"
}

# Lightweight Directory Access Protocol (LDAP) Server
# is an open and cross platform software protocol that is used for directory services authentication.

slap_disable() {
    if dpkg -l | grep -qw slapd; then
        echo "slapd is installed. Proceeding with removal."
        # Using apt-get purge to remove slapd and its configuration files
        sudo apt-get purge -y slapd
        echo "$STEP_ICON slapd has been removed successfully."
    else
        echo "$STEP_ICON slapd is not installed. No action needed."
    fi

    if ps aux | grep nfsd; then
    echo "NSF is installed in the computer"
    apt-get purge -y rpcbind
    echo "$STEP_ICON rpcbind removed" 
    fi
}

nfs_disable() {
    read -p "Do you want to disable NFS  (y/n) ?" nfs_disabling
    if [[ "$nfs_disabling" == "y | yes" ]]; then
        if ps aux | grep nfs-kernel-server; then
        echo "NFS is installed in the machine"
        systemctl disable nfs-kernel-server
        else 
        echo "$STEP_ICON NFS is not installed. No action needed."
        fi
    fi
}

process_accounting() {
    # Linux process accounting keeps track of all sorts of details about which commands have been run on the server, who ran them, when, etc.
    apt-get --yes --force-yes install acct
    echo "$STEP_ICON Bellow will be show somes usefull security related informations"
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


disable_compilers() {
    chmod 000 /usr/bin/byacc
    chmod 000 /usr/bin/yacc
    chmod 000 /usr/bin/bcc
    chmod 000 /usr/bin/kgcc
    chmod 000 /usr/bin/cc
    chmod 000 /usr/bin/gcc
    chmod 000 /usr/bin/*c++
    chmod 000 /usr/bin/*g++
    echo "$STEP_ICON  differents compilers disabled" 
    # 755 to bring them back online
    # It is better to restrict access to them
    # unless you are working with a specific one
}


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
    
    #### Probably add also below,  ### but verify what it do
    # "rsh-redone-server"
    # "yp-tools"
    # "xinetd" 
    # "nis"  
    # "tftpd" 
    # "atftpd" 
    # "tftpd-hpa" 
)

purge_useless_packages() {
    for appli in "${packages[@]}"; do
        if ps aux | grep -v grep | grep -w "${appli}" > /dev/null; then
            echo "Using ps: $appli is Running"
            sudo apt-get purge -y "$appli"
            sudo apt-get --purge remove -y "$appli"
            echo "$STEP_ICON  $appli removed" 
        else
            echo "$STEP_ICON Using ps: $appli is Not running"
        fi
    done
}

##### Checking security module in place
# AppArmor ("Application Armor") is a Linux kernel security module that allows the system administrator to restrict programs' capabilities with per-program profiles.
# Check if apparmor is installed command is available
check_apparmor() {
    if command -v apparmor_status >/dev/null 2>&1; then
        echo "$STEP_ICON AppArmor already installed."
        # Execute apparmor_status with sudo and pipe to grep to check for active profiles
        if apparmor_status | grep -q "profiles are loaded."; then
            echo "$STEP_ICON AppArmor is active."
        else
            echo "$STEP_ICON AppArmor already installed but not active or not functioning correctly."
        fi
    else
        echo "$STEP_ICON AppArmor is not installed."
    fi
}

# Security-Enhanced Linux (SELinux) is a Linux kernel security module that provides a mechanism for supporting access control security policies, including mandatory access controls (MAC). 
# The NSA Security-enhanced Linux Team describes NSA SELinux as[5] a set of patches to the Linux kernel and utilities to provide a strong, flexible, mandatory access control (MAC) architecture into the major subsystems of the kernel. 
# Function to check if SELinux is installed
check_selinux() {
    if command -v getenforce >/dev/null 2>&1; then
        echo "$STEP_ICON SELinux already installed."
        # Check if SELinux is enforcing, permissive, or disabled
        echo "$STEP_ICON SELinux status: $(getenforce)"
    else
        echo "$STEP_ICON SELinux is not installed."
    fi
}

#!/bin/bash

SSH_CONFIG="/etc/ssh/ssh_config"
SSHD_CONFIG="/etc/ssh/sshd_config"
PORT=1754

update_sshd_config() {
    local file="$1"
    local setting="$2"
    local value="$3"
    
    # Build the line to write or replace in the config file
    local new_line="$setting $value"
    
    # Regex to find the existing setting, commented or not, handling whitespace
    local setting_regex="^\s*#?\s*$setting\s.*$"

    # Adding debug output to check which path is taken
    echo "Attempting to update $setting to $value in $file..."

    # Check if the setting exists and replace it, or add it if it doesn't
    if grep -qP "$setting_regex" "$file"; then
        echo "Setting found, updating..."
        sed -i -r "s|$setting_regex|$new_line|" "$file"
        echo "Updated $setting to $value in $file."
    else
        echo "Setting not found, adding..."
        echo "$new_line" >> "$file"
        echo "Added $setting with value $value to $file."
    fi
}

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" >&2
    exit 1
fi

# Apply the specific settings to sshd_config
echo "Applying settings to $SSHD_CONFIG..."


declare -A settings_ssh_daemon=(
    [Port]="$PORT"
    [LogLevel]="VERBOSE"
    [LoginGraceTime]="2m"
    [PermitRootLogin]="prohibit-password"
    [MaxAuthTries]="4"
    [MaxSessions]="6"
    [PubkeyAuthentication]="yes"
    [PasswordAuthentication]="yes"
    [PermitEmptyPasswords]="no"
    [ChallengeResponseAuthentication]="no"
    [UsePAM]="no"
    [AllowAgentForwarding]="yes"
    [AllowTcpForwarding]="yes"
    [X11Forwarding]="no"
    [X11UseLocalhost]="no"
    [PrintMotd]="no"
    [PermitUserEnvironment]="no"
    [ClientAliveCountMax]="3"
    [PermitTunnel]="no"
    [ChrootDirectory]="none"
    [Banner]="none"
    [AcceptEnv]="LANG LC_*"
    [Subsystem]="sftp /usr/lib/openssh/sftp-server"
    [DebianBanner]="no"
    [ClientAliveInterval]="10m"
    [GSSAPIAuthentication]="no"
    [Protocol]="2"
    [UsePrivilegeSeparation]="no"
)

# Loop through all settings and apply them
for setting in "${!settings_ssh_daemon[@]}"; do
    update_sshd_config "$SSHD_CONFIG" "$setting" "${settings_ssh_daemon[$setting]}"
done


# Function to update SSH configuration settings, both client and server
update_ssh_config() {
    local file="$1"
    local setting="$2"
    local value="$3"
    
    # Build the line to write or replace in the config file
    local new_line="$setting $value"
    
    # Regex to find the existing setting, commented or not, with robust whitespace handling
    local setting_regex="^\s*#?\s*$setting\b.*$"

    # Check if the setting exists and replace it, or add it if it doesn't
    if grep -qP "$setting_regex" "$file"; then
        # Setting exists, replace it
        sed -i -r "s|$setting_regex|$new_line|" "$file"
        echo "Updated $setting to $value in $file."
    else
        # Setting does not exist, add it
        echo "$new_line" >> "$file"
        echo "Added $setting with value $value to $file."
    fi
}

# Ensure the script is run as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root" >&2
    exit 1
fi

declare -A settings_client=(
    [ForwardAgent]="yes"
    [ForwardX11]="no"
    [ForwardX11Trusted]="no"
    [PasswordAuthentication]="no"
    [HostbasedAuthentication]="no" # no verified     
    #   GSSAPIAuthentication no
    #   GSSAPIDelegateCredentials n
    #   GSSAPIKeyExchange no
    #   GSSAPITrustDNS no
    #   BatchMode no
    #   CheckHostIP yes
    #   AddressFamily any
    #   ConnectTimeout 0
    #   StrictHostKeyChecking ask
    #   IdentityFile ~/.ssh/id_rsa
    #   IdentityFile ~/.ssh/id_dsa
    #   IdentityFile ~/.ssh/id_ecds
    #   IdentityFile ~/.ssh/id_ed25
    [Port]="$PORT"
    #   Ciphers aes128-ctr,aes192-c
    #   MACs hmac-md5,hmac-sha1,uma
    #   EscapeChar ~
    [Tunnel]="no"
    [TunnelDevice]="any:any"
    #   PermitLocalCommand no
    #   VisualHostKey no
    #   ProxyCommand ssh -q -W %h:%
    #   RekeyLimit 1G 1h
    #   SendEnv LANG LC_*
    #   HashKnownHosts yes
    #   GSSAPIAuthentication yes
)

echo "Applying settings to SSH client configuration..."

for setting in "${!settings_client[@]}"; do
    update_ssh_config "$SSH_CONFIG" "$setting" "${settings_client[$setting]}"
done

echo "SSH client configuration updated. No need to restart the SSH daemon for client config changes."

# Restart SSHD to apply changes
echo "Restarting SSHD..."
systemctl restart sshd
echo "SSH configuration completed."

kerberos_setup_sshd() {
    # Prompt the user to confirm UPnP deactivation
   echo "Kerberos is a computer-network authentication protocol that works on the basis of tickets to allow nodes communicating over a non-secure network to prove their identity to one another in a secure manner."
   read -p "Do you use Kerberos and want to disable it ? (y/n): " kerberos_response

    kerberos_response="${kerberos_response,,}"  # ,, converts to lowercase

    echo "KerberosTicketCleanup no" >> "$SSHD_CONFIG"
    echo "KerberosGetAFSToken no" >>"$SSHD_CONFIG"

    if [[ "$kerberos_response" == "y" ]]; then
        echo "$STEP_ICON Disabling Kerberos Authentification in sshd_config..."

    if grep -q "^KerberosAuthentication no" "$SSHD_CONFIG"; then
        echo "$STEP_ICON KerberosOrLocalPassword is already set to NO."
    else
        # Replace or uncomment DebianBanner setting
        sed -i '/^#*KerberosAuthentication /c\KerberosAuthentication no' "$SSHD_CONFIG"
        if ! grep -q "^KerberosAuthentication no" "$SSHD_CONFIG"; then
            echo "KerberosAuthentication no" >> "$SSHD_CONFIG"
        fi
        echo "$STEP_ICON KerberosAuthentication set to no"
    fi

    if grep -q "^KerberosOrLocalPassword no" "$SSHD_CONFIG"; then
        echo "$STEP_ICON KerberosOrLocalPassword is already set to NO."
    else
        # Replace or uncomment DebianBanner setting
        sed -i '/^#*KerberosOrLocalPassword /c\KerberosOrLocalPassword no' "$SSHD_CONFIG"
        if ! grep -q "^KerberosOrLocalPassword no" "$SSHD_CONFIG"; then
            echo "KerberosOrLocalPassword no" >> "$SSHD_CONFIG"
        fi
        echo "$STEP_ICON KerberosOrLocalPassword set to no"
    fi

    elif [[ "$kerberos_response" == "n" ]]; then
        echo "$STEP_ICON Kerberos authentification has not been disabled."
    else
        echo "$STEP_ICON Invalid input. Please enter 'y' for yes or 'n' for no."
    fi
}



##### firewall implementation
set_ufw() {
    if ! command -v ufw &> /dev/null; then
        echo "UFW is not installed. Installing UFW..."
        sudo apt update
        sudo apt install ufw -y
        echo "UFW installed successfully."
    fi

    echo "Enabling UFW and setting default policies..."
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw enable

    port_list=(1754 80 8080)

    # Allow connections on the specified ports
    for port in "${port_list[@]}"; do
        echo "Allowing connections on port $port..."
        sudo ufw allow $port/tcp
    done

    ufw allow ssh

    echo "Showing UFW status..."
    sudo ufw status verbose

    echo "UFW has been configured and is running."
}

# UPnP (Universal Plug and Play)
upnp_desactivation() {
    # Prompt the user to confirm UPnP deactivation
   echo "Universal Plug and Play (UPnP) allows network devices like media servers and routers to discover each other."
   echo "Disabling UPnP might impact services like media centers (e.g., Plex) or network devices (e.g., some WiFi routers)."
   read -p "Do you wish to disable UPnP? (y/n): " upnp_response

    # Convert response to lowercase to simplify the conditional check
    upnp_response="${upnp_response,,}"  # ,, converts to lowercase

    # Check user input and apply the firewall rule if confirmed
    if [[ "$upnp_response" == "y" ]]; then
        echo "Disabling UPnP..."
        ufw deny proto udp from any to any port 1900
        echo "$STEP_ICON UPnP has been disabled."
    elif [[ "$upnp_response" == "n" ]]; then
        echo "$STEP_ICON UPnP has not been disabled."
    else
        echo "$STEP_ICON Invalid input. Please enter 'y' for yes or 'n' for no."
    fi
}

# Intrusion prevention software framework
set_fail2ban() {
    # Install fail2ban if not already installed
    if ! dpkg -l | grep -qw fail2ban; then
        echo "Installing fail2ban..."
        apt-get update
        apt-get install -y fail2ban
    else
        echo "fail2ban is already installed."
    fi

    # Check if jail.local needs to be created or appended
    if [ ! -f /etc/fail2ban/jail.local ]; then
        echo "Creating /etc/fail2ban/jail.local with ssh-ddos jail..."
        echo "[ssh-ddos]" > /etc/fail2ban/jail.local
        echo "enabled = true" >> /etc/fail2ban/jail.local
        echo "port = ssh" >> /etc/fail2ban/jail.local
        echo "filter = sshd" >> /etc/fail2ban/jail.local
        echo "logpath = /var/log/auth.log" >> /etc/fail2ban/jail.local
        echo "maxretry = 6" >> /etc/fail2ban/jail.local
    else
        echo "/etc/fail2ban/jail.local already exists. Appending configuration for ssh-ddos..."
        grep -q "[ssh-ddos]" /etc/fail2ban/jail.local || {
            echo "[ssh-ddos]" >> /etc/fail2ban/jail.local
            echo "enabled = true" >> /etc/fail2ban/jail.local
            echo "port = ssh" >> /etc/fail2ban/jail.local
            echo "filter = sshd" >> /etc/fail2ban/jail.local
            echo "logpath = /var/log/auth.log" >> /etc/fail2ban/jail.local
            echo "maxretry = 6" >> /etc/fail2ban/jail.local
        }
    fi

    # Restart fail2ban to apply changes
    echo "Restarting fail2ban service..."
    systemctl restart fail2ban

    # Restart SSH service
    echo "Restarting SSH service..."
    systemctl restart ssh

    # Check if fail2ban is installed and running
    systemctl status fail2ban --no-pager

    # Check the log for errors
    echo "Checking fail2ban log for errors..."
    cat /var/log/fail2ban.log
}

set_chkrootkit() {
    apt-get --yes install chkrootkit
    chkrootkit
}

future_implementations() {
    echo -e "Future implementation can be added in the future : ClamAv, Crowdsec, etc... \n Hardening can still be improved"
}

main() {
    # setup_ssh_ed25519
    sys_upgrades
    unattended_upg
    disable_root
    purge_telnet
    purge_nfs
    purge_whoopsie
    harden_ssh_brute
    logwatch_reporter
    purge_atd
    disable_avahi
    disable_cups
    slap_disable
    process_accounting
    disable_compilers
    # firewall_setup
    check_apparmor
    check_selinux
    harden_sshd_config
    kerberos_setup_sshd
    upnp_desactivation
    # kernel_tuning
    set_ufw
    set_fail2ban
    # set_chkrootkit
    purge_useless_packages
    future_implementations
}

main "$@"

echo "Test that ssh connexion stil work with the new port : "${PORT}""