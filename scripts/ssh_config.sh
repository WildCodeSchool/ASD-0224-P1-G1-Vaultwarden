SSH_CONFIG="/etc/ssh/ssh_config"  
SSHD_CONFIG="/etc/ssh/sshd_config"  
declare -i PORT=1754

harden_sshd_config() {

    CINTERVAL="10m"

    echo "$SSH_CONFIG"
    echo "$SSHD_CONFIG"
    echo "Port to $PORT" 
    echo "Configuring $SSH_CONFIG and $SSHD_CONFIG for port $PORT."
    # Ensure the script is run as root
    
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root" 1>&2
        exit 1
    fi

    declare -A settings_ssh
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

        declare -A settings_ssh_daemon
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
        local setting_regex="^#?\s*$setting\s+.*$"
        local setting_found=$(grep -E "$setting_regex" "$file")

        if [[ "$setting_found" ]]; then
            sed -i "/$setting_regex/c\\$setting $value" "$file"
            echo "Updated $setting to $value in $file."
        else
            echo "$setting $value" >> "$file"
            echo "Added $setting with value $value to $file."
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

harden_sshd_config
