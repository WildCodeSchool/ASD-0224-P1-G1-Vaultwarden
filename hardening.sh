#!/bin/bash

echo "script started"
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



##############


new_port=2269

apt update
apt upgrade

# port modification

nano /etc/ssh/sshd_config
### modification in this line to modify port
service ssh restart
echo "Test that ssh connexion stil work with the new port : "${new_port}""

# firewall implementation
sudo apt install fail2ban
sudo nano /etc/fail2ban/jail.local

#### Adapt  [ssh-ddos] part to "enabled = true"
/etc/init.d/fail2ban restart
