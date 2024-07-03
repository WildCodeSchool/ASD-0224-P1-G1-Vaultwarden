#!/bin/bash

SSH_CONFIG="/etc/ssh/ssh_config"  
SSHD_CONFIG="/etc/ssh/sshd_config"  

harden_sshd_config() {
    CINTERVAL="10m"
    PORT=1754

    # Debug information
    echo "Configuring $SSH_CONFIG and $SSHD_CONFIG for port $PORT."

    # Ensure the script is run as root
    if [[ $EUID -ne 0 ]]; then
        echo "This script must be run as root" 1>&2
        exit 1
    fi

    declare -A settings_ssh
    settings_ssh=(
        [Port]="$PORT"
        [ForwardAgent]="yes"
        [ForwardX11]="no"
        [ForwardX11Trusted]="no"
        [PasswordAuthentication]="no"
        [HostbasedAuthentication]="no"
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

    # Apply settings to ssh_config
    for setting in "${!settings_ssh[@]}"; do
        apply_setting "$SSH_CONFIG" "$setting" "${settings_ssh[$setting]}"
    done

    # Apply settings to sshd_config
    for setting in "${!settings_ssh_daemon[@]}"; do
        apply_setting "$SSHD_CONFIG" "$setting" "${settings_ssh_daemon[$setting]}"
    done
}

apply_setting() {
    local file=$1
    local setting=$2
    local value=$3
    local setting_regex="^#*$setting .*$"

    if grep -q "^$setting $value" "$file"; then
        echo "$setting is already set to $value."
    else
        sed -i "/$setting_regex/c\\$setting $value" "$file"
        if ! grep -q "^$setting $value" "$file"; then
            echo "$setting $value" >> "$file"
        fi
        echo "$setting set to $value in $file."
    fi
}

# Execute the function
harden_sshd_config
