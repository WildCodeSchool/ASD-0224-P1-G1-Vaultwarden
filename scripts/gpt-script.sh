#!/bin/bash

SSHD_CONFIG="/etc/ssh/sshd_config"
declare -i PORT=1754

# Function to update SSHD configuration settings
update_sshd_config() {
    local file="$1"
    local setting="$2"
    local value="$3"
    
    # Build the line to write or replace in the config file
    local new_line="$setting $value"
    
    # Regex to find the existing setting, commented or not
    local setting_regex="^#?\s*$setting\s+.*$"

    # Check if the setting exists and replace it, or add it if it doesn't
    if grep -qE "$setting_regex" "$file"; then
        # Setting exists, replace it
        sed -i "s/$setting_regex/$new_line/" "$file"
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

# Apply the specific settings to sshd_config
echo "Applying settings to $SSHD_CONFIG..."

# List of settings and values to be configured
declare -A settings=(
    [Port]="${PORT}"
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
    [Protocol]="2"
    [UsePrivilegeSeparation]="no"
    [GSSAPIAuthentication]="yes"

)

# Loop through all settings and apply them
for setting in "${!settings[@]}"; do
    update_sshd_config "$SSHD_CONFIG" "$setting" "${settings[$setting]}"
done



# Restart the sshd service to apply changes
systemctl restart sshd
echo "sshd configuration updated and service restarted."
