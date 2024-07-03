#!/bin/bash

SSH_CONFIG="/etc/ssh/ssh_config"  
SSHD_CONFIG="/etc/ssh/sshd_config"  
declare -i PORT=1754

harden_sshd_config() {

    echo "$SSH_CONFIG"
    echo "$SSHD_CONFIG"
    echo "Port set to $PORT" 
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
        [HostbasedAuthentication]="no"
        [Port]="$PORT"
        [Tunnel]="no"
        [TunnelDevice]="any:any"
    )

    declare -A settings_ssh_daemon
    settings_ssh_daemon=(
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
            echo "Updated $setting to $value in $file."
        else
            # If not found, simply append it
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
