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
ufw status 2>> /dev/null >&2
if [[ "$?" -eq 1 ]];then
 echo "Skipping UFW config as it does not seem to be installed - check log to know more"
else
 apt install ufw
 "${STEP}" ufw added
fi

# Remove telemetry and useless layers
purge_whoopsie() {
    # Although whoopsie is useful(a crash log sender to ubuntu)
    # less layers = more sec
    apt-get --yes purge whoopsie
}


##############

new_port=2269

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
