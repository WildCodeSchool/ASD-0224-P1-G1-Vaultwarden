#!/bin/bash

# The administrator has to know the root password and add the execution rights to the script before launching it
# Variables

dir="/tmp/install_log.txt"
install_date="$(date +'%Y_%m_%d')"
space=echo "" >> "$dir"
# Sys and app update 
echo "System update. Please, enter root password when asked to: "
sudo apt update && sudo apt upgrade -y  
if [ $? -ne 0 ]; then
    echo "Echec de la mise à jour. Please, check the error message."
fi
echo "apt updated and ready to run."
echo "$install_date - Update and upgrades done." > $dir
$space

# Apps and packages install

echo "VaultWarden's required applications are about to be installed."

# build-essential install
echo "Installing build-essential..."
sudo apt install -qqy build-essential
if [ $? -ne 0 ]; then
    echo "Could not install build-essential. Please, check the error message."
fi
echo "Install complete"
echo "$install_date - Update and upgrades done on " + $(hostname) + "." >> $dir
$space

# Installing curl
echo "Installing curl..."
sudo apt install -qqy curl
if [ $? -ne 0 ]; then
    echo "Could not install curl. Please, check the error message."
fi
echo "curl install complete"
echo "$install_date - Installed curl on " + $(hostname) + "." >> $dir
$space

# Installing git
echo "Installing git..."
sudo apt install -qqy git 
if [ $? -ne 0 ]; then
    echo "Could not install git. Please, check the error message."
fi
echo "Git install complete"
echo "$install_date - Installed git on $(hostname)." >> $dir
$space

# Installing nginx pour reverse-proxy
echo "Installing Nginx..."
sudo apt install -qqy nginx 
if [ $? -ne 0 ]; then
    echo "Could not install nginx. Please, check the error message."
fi
echo "Install complete"
echo "$install_date - Installed nginx on $(hostname)." >> $dir
$space

# Installing Vaultwarden required libraries
echo "Installing Vaultwarden required libraries"
sudo apt install -qqy libssl-dev libsqlite3-dev libmariadb libmariadb-dev-compat libpq-dev
if [ $? -ne 0 ]; then
    echo "Could not install some or all the libraries. Please, check the error message(s)"
fi
echo "Install complete"
echo "$install_date - Installed Vaultwarden required libraries on $(hostname)." >> $dir
$space

sudo curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
#nvm use 16
#npm install -g 8.11
npm install
echo "$install_date - Installed npm on $(hostname)." >> $dir
$space

# Node.js installation check
echo "Checking Node.js install ..."
node --version
echo "$install_date - Checked node version: $(node --version) on $(hostname)." >> $dir
$space

npm --version
echo "$install_date - Checked npm version: $(npm --version) on $(hostname)." >> $dir
$space

# Makes the following script executable and runs it
chmod +x /root/scritps/script_log.sh
/root/scripts/script_log.sh

# log des install faites avec apt il faudrait peut être voir pour l'exploiter, pour l'instant je n'ai pas trouvé mieux
# nano /var/log/apt/history.log