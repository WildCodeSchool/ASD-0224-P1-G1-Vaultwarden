#!/bin/bash

# The administrator has to know the root password and add the execution acl to the script before launching it

# Sys and app update 
echo "System update. Please, enter root password when asked to: "
sudo apt update && sudo apt upgrade -y  
if [ $? -ne 0 ]; then
    echo "Echec de la mise à jour. Please, check the error message."
fi
echo "apt updated and ready to run."

# Apps and packages install

echo "VaultWarden's required applications are about to be installed."

# build-essential install
echo "Installing build-essential..."
sudo apt install -qq build-essential
if [ $? -ne 0 ]; then
    echo "Could not install build-essential. Please, check the error message."
fi
echo "Install complete"

# Installing curl
echo "Installing curl..."
sudo apt install -qq curl
if [ $? -ne 0 ]; then
    echo "Could not install curl. Please, check the error message."
fi
echo "Install complete"

# Installing git
echo "Installing git..."
sudo apt install -qq git 
if [ $? -ne 0 ]; then
    echo "Could not install git. Please, check the error message."
fi
echo "Install complete"

# Installing nginx pour reverse-proxy
echo "Installing Nginx..."
sudo apt install -qq nginx 
if [ $? -ne 0 ]; then
    echo "Could not install nginx. Please, check the error message."
fi
echo "Install complete"

# Installing Vaultwarden required libraries
echo "Installing Vaultwarden required libraries"
sudo apt install -qq libssl-dev libsqlite3-dev libmariadb libmariadb-dev-compat libpq-dev
if [ $? -ne 0 ]; then
    echo "Could not install some or all the libraries. Please, check the error message(s)"
fi
echo "Install complete"

sudo curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
#nvm use 16
#npm install -g 8.11
npm install

# Node.js installation check
echo "Checking Node.js install ..."
node --version
npm --version

# log des install faites avec apt il faudrait peut être voir pour l'exploiter, pour l'instant je n'ai pas trouvé mieux
# nano /var/log/apt/history.log

# Makes the following script executable and runs it
chmod +x /root/scritps/script_final-log.sh
/root/scripts/script_final-log.sh