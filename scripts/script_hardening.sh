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

# Check if UFW is installed
ufw status 2>>/dev/null >&2
if [[ "$?" -eq 1 ]]; then
    echo "Skipping UFW config as it does not seem to be installed - check log to know more"
else
    apt install ufw
    "${STEP_ICON}" ufw added
fi

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

# Perform the checks


harden_sshd_config() {
    CINTERVAL="10m"
    echo "Differents variables choosen :"
    echo "Port to $PORT" 

    # Ensure the script is run as root
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root" 1>&2
        exit 1
    fi

    apt install openssh-client
    apt-get install openssh-server -y

########################################################## SSH_CLIENT config

    settings_ssh=(
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
########################################################## SSH_DAEMON config
        settings_ssh_daemon=(
        [Port]="$PORT"
        #AddressFamily any
        #ListenAddress 0.0.0.0
        #ListenAddress ::

        #HostKey /etc/ssh/ssh_host_rsa_key
        #HostKey /etc/ssh/ssh_host_ecdsa_key
        #HostKey /etc/ssh/ssh_host_ed25519_key

        # Ciphers and keying
        #RekeyLimit default none

        # Logging
        #SyslogFacility AUTH
        [LogLevel]="VERBOSE"

        # Authentication:

        [LoginGraceTime]="2m"
        [PermitRootLogin]="prohibit-password"
        #StrictModes yes
        [MaxAuthTries]="4"
        [MaxSessions]="6"
        [PubkeyAuthentication]="yes"

        # Expect .ssh/authorized_keys2 to be disregarded by default in future.
        #AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys2

        #AuthorizedPrincipalsFile none

        #AuthorizedKeysCommand none
        #AuthorizedKeysCommandUser nobody

        # For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
        #HostbasedAuthentication no
        # Change to yes if you don't trust ~/.ssh/known_hosts for
        # HostbasedAuthentication
        #IgnoreUserKnownHosts no
        # Don't read the user's ~/.rhosts and ~/.shosts files
        #IgnoreRhosts yes

        # To disable tunneled clear text passwords, change to no here!
        [PasswordAuthentication]="yes"
        [PermitEmptyPasswords]="no"

        # Change to yes to enable challenge-response passwords (beware issues with
        # some PAM modules and threads)
        [ChallengeResponseAuthentication]="no"


        # GSSAPI options
        #GSSAPIAuthentication no
        #GSSAPICleanupCredentials yes
        #GSSAPIStrictAcceptorCheck yes
        #GSSAPIKeyExchange no

        # Set this to 'yes' to enable PAM authentication, account processing,
        # and session processing. If this is enabled, PAM authentication will
        # be allowed through the ChallengeResponseAuthentication and
        # PasswordAuthentication.  Depending on your PAM configuration,
        # PAM authentication via ChallengeResponseAuthentication may bypass
        # the setting of "PermitRootLogin without-password".
        # If you just want the PAM account and session checks to run without
        # PAM authentication, then enable this but set PasswordAuthentication
        # and ChallengeResponseAuthentication to 'no'.
        [UsePAM]="no"

        [AllowAgentForwarding]="yes"
        [AllowTcpForwarding]="yes"
        #GatewayPorts no
        [X11Forwarding]="no"
        #X11DisplayOffset 10
        X11UseLocalhost="no"
        #PermitTTY yes
        [PrintMotd]="no"
        #PrintLastLog yes
        #TCPKeepAlive yes
        [PermitUserEnvironment]="no"
        #Compression delayed
        #ClientAliveInterval 0
        [ClientAliveCountMax]="3"
        #UseDNS no
        #PidFile /var/run/sshd.pid
        #MaxStartups 10:30:100
        [PermitTunnel]="no"
        [ChrootDirectory]="none"
        #VersionAddendum none

        # no default banner path
        [Banner]="none"

        # Allow client to pass locale environment variables
        [AcceptEnv]="LANG LC_*"

        # override default of no subsystems
        [Subsystem]="sftp	/usr/lib/openssh/sftp-server"

        # Example of overriding settings on a per-user basis
        #Match User anoncvs
        #	PermitTTY no
        #	ForceCommand cvs server

        [DebianBanner]="no"
        [ClientAliveInterval]="10m"  # Adjust this to your desired interval
        
        [GSSAPIAuthentication]="no"
        # [HostBasedAuthentification]="no"
        # [StrictHostKeyChecking]="ask"
        [Protocol]="2"
        [UsePrivilegeSeparation]="no" # Setting privilege separation helps to secure remote ssh access. Once a user is authenticated the sshd daemon creates a child process which has the privileges of the authenticated user and this then handles incoming network traffic. The aim of this is to prevent privilege escalation through the initial root process.
        # ChallengeResponseAuthentication # Don't know if usefull or not
    )

  update_config_file() {
        local file=$1
        local setting=$2
        local value=$3
        # Define the regex to find settings potentially commented
        local setting_regex="^\s*#?\s*$setting\s+.*$"

        # First, remove comments if they exist
        sed -i "s/^#\s*\($setting\s.*\)$/\1/" "$file"

        # Now, check if the setting already exists and update it
        local setting_found=$(grep -E "^$setting\s" "$file")
        if [[ "$setting_found" ]]; then
            # If found, replace the existing line with the new value
            sed -i "s/^$setting\s.*$/$setting $value/" "$file"
            echo "$STEP_ICON Updated $setting to $value in $file."
        else
            # If not found, simply append it
            echo "$setting $value" >> "$file"
            echo "$STEP_ICON Added $setting with value $value to $file."
        fi
    }
    
    # Apply settings to ssh_config
    for setting in "${!settings_ssh[@]}"; do
        update_config_file "$SSH_CONFIG" "$setting" "${settings_ssh[$setting]}"
    done

    # Apply settings to sshd_config
    for setting in "${!settings_ssh_daemon[@]}"; do
        update_config_file "$SSHD_CONFIG" "$setting" "${settings_ssh_daemon[$setting]}"
    done
}

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

set_chkrootkit() {
    apt-get --yes install chkrootkit
    chkrootkit
}

##### firewall implementation
set_ufw() {
    # Check if UFW is installed, if not, install it
    if ! command -v ufw &> /dev/null
    then
        echo "UFW is not installed. Installing UFW..."
        sudo apt-get update
        sudo apt-get install ufw -y
    fi
    # Enable UFW
    echo "Enabling UFW..."
    sudo ufw enable

    # Declare an array of ports to allow
    declare -i port_list=(
        80
        8080
        443
        1754
    )

    # Allow connections on the specified ports
    for port in "${port_list[@]}"
    do
        echo "Allowing connections on port $port..."
        sudo ufw allow $port/tcp
    done

    # Show UFW status
    echo "Showing UFW status..."
    sudo ufw status verbose

    echo "UFW has been configured and is running."
}

# Intrusion prevention software framework
set_fail2ban() {
    apt install fail2ban
    echo "[ssh-ddos]" > /etc/fail2ban/jail.local 
    echo "enabled = true" >> /etc/fail2ban/jail.local
    ## If need to copy paste
    # [ssh-ddos]
    # enabled = true
    /etc/init.d/fail2ban restart
    service ssh restart


    # Check if fail2ban is installed and running
    sudo systemctl status fail2ban

    # If not running, try starting it
    sudo systemctl start fail2ban

    # Check the log again for errors
    cat /var/log/fail2ban.log
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







# EOF
# )
# # Execute the commands on the remote server
# ssh -i $SSH_KEY -p $REMOTE_PORT $REMOTE_USER@$REMOTE_HOST "$REMOTE_COMMANDS"


##### Add later with adaptation the code below,  


# https://ittavern.com/ssh-server-hardening/

# Disable tunneling and port forwarding #
# AllowAgentForwarding no
# AllowTcpForwarding no
# PermitTunnel no

# Disabling those functions makes it more difficult to use the server as a jump host to gain access to the connected networks, malicious or not. Most servers do not need those functions enabled, but to learn more, feel free to check my article about SSH tunneling and port forwarding.

# Disable unused authentification methods #
# KerberosAuthentication no
# GSSAPIAuthentication no
# ChallengeResponseAuthentication
# It highly depends on your needs, but if an authentification method is unused, it should be disabled as it increases the attack surface to exploits and vulnerabilities.
# Side note: Please ensure you don't disable the only method you can log in to prevent a lockout. 

# PermitTunnel no
# # Signification : Le paramètre PermitTunnel dans la configuration d'OpenSSH contrôle la possibilité d'établir des tunnels de données SSH. 
# Lorsque cette fonction est activée, les utilisateurs peuvent créer des tunnels qui encapsulent d'autres types de trafic (comme le trafic TCP/IP) dans une connexion SSH.
# # Configuration recommandée : Bien que les tunnels SSH puissent être utiles pour sécuriser le trafic entre des points distants, 
# ils peuvent également être utilisés de manière inappropriée pour contourner les politiques de sécurité réseau. 
# Par exemple, un utilisateur pourrait établir un tunnel SSH pour contourner un pare-feu ou un filtre de contenu. 
# Si les tunnels SSH ne sont pas nécessaires pour vos opérations normales, il est recommandé de désactiver cette fonctionnalité pour réduire la surface d'attaque potentielle. 
# Configurez PermitTunnel no dans votre fichier de configuration SSH pour désactiver la création de tunnels.

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

# echo " - Changing value PermitUserEnvironment to no."
# if [ $(cat /etc/ssh/sshd_config | grep PermitUserEnvironment | wc -l) -eq 0 ]; then
#   echo "PermitUserEnvironment no" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#PermitUserEnvironment [a-zA-Z0-9]*/s/#PermitUserEnvironment [a-zA-Z0-9]*/PermitUserEnvironment no/' /etc/ssh/sshd_config
#   sed -i -e '1,/PermitUserEnvironment [a-zA-Z0-9]*/s/PermitUserEnvironment [a-zA-Z0-9]*/PermitUserEnvironment no/' /etc/ssh/sshd_config
# fi



# echo " - Changing value LoginGraceTime to 2m."
# if [ $(cat /etc/ssh/sshd_config | grep LoginGraceTime | wc -l) -eq 0 ]; then
#   echo "LoginGraceTime 2m" >> /etc/ssh/sshd_config
# else
#   sed -i -e '1,/#LoginGraceTime [a-zA-Z0-9]*/s/#LoginGraceTime [a-zA-Z0-9]*/LoginGraceTime 2m/' /etc/ssh/sshd_config
#   sed -i -e '1,/LoginGraceTime [a-zA-Z0-9]*/s/LoginGraceTime [a-zA-Z0-9]*/LoginGraceTime 2m/' /etc/ssh/sshd_config
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

# echo " - Changing SSH Daemon Configuraion File Permissions."
# chmod 600 /etc/ssh/sshd_config

# echo " - Restarting SSH Daemon."
# systemctl restart sshd

# echo "[DONE]"
# exit 0
