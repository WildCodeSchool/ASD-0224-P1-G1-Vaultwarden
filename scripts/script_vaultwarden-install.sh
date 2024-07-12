#!/bin/bash

# The administrator has to know the root password and add the execution rights to the script before launching it
# Variables

dir="/home/install_log.txt"
install_date="$(date +'%Y_%m_%d')"
vault_dir="/home/vaultwarden/logs"

# Sys and app update 
echo -e "System update. Please, enter root password when asked to: "
sudo apt update && sudo apt upgrade -y  
if [ $? -ne 0 ]; then
    echo -e "Echec de la mise à jour. Please, check the error message."
fi
echo -e "apt updated and ready to run."
echo -e "$install_date - Update and upgrades done. \n" > $dir

# Apps and packages install

echo -e "VaultWarden's required applications are about to be installed."

# build-essential install
echo -e "Installing build-essential..."
sudo apt install -qqy build-essential
if [ $? -ne 0 ]; then
    echo -e "Could not install build-essential. Please, check the error message."
fi
echo -e "Install complete"
echo -e "$install_date - Update and upgrades done on $(hostname). \n" >> $dir

# Installing curl
echo -e "Installing curl..."
sudo apt install -qqy curl
if [ $? -ne 0 ]; then
    echo -e "Could not install curl. Please, check the error message."
fi
echo -e "curl install complete"
echo -e -e "$install_date - Installed curl on $(hostname). \n" >> $dir

# Installing git
echo -e "Installing git..."
sudo apt install -qqy git 
if [ $? -ne 0 ]; then
    echo -e "Could not install git. Please, check the error message."
fi
echo -e "Git install complete"
echo -e "$install_date - Installed git on $(hostname). \n" >> $dir

#Clone vaultwarden repo at "/home"
cd /home
git clone https://github.com/dani-garcia/vaultwarden.git

echo -e "$install_date - Downloaded github repo on $(hostname). \n" >> $dir

#Download pre-build web
cd /home/vaultwarden
wget https://github.com/dani-garcia/bw_web_builds/releases/download/v2024.5.1/bw_web_v2024.5.1.tar.gz
tar -xvzf bw_web_v2024.5.1.tar.gz

#Rocket - Install & Prérequis
apt install -y pkg-config libssl-dev libmariadb-dev-compat libmariadb-dev gcc
if [ $? -ne 0 ]; then
    echo -e "Could not install some or all the libraries. Please, check the error message(s)"
fi
echo -e "Install complete"
echo -e "$install_date - Installed Vaultwarden required libraries on $(hostname). \n" >> $dir

snap install rustup --classic
if [ $? -ne 0 ]; then
    echo -e "Could not install rustup. Please, check the error message."
fi
echo -e "Install complete"
echo -e "$install_date - Installed rustup on $(hostname). \n" >> $dir

# mkdir $vault_dir && mv $dir "$vault_dir/install_log.txt"

rustup default stable

mkdir data/

## Creation du service Vaultwarden
# Définir les variables
SERVICE_NAME="vaultwarden"
USER_NAME=$(whoami)
PROJECT_DIR=/home/vaultwarden
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# Créer le fichier de service
echo "Creating service file at ${SERVICE_FILE}..."
sudo bash -c "cat > ${SERVICE_FILE}" <<EOL
[Unit]
Description=Vaultwarden
After=network.target

[Service]
User=${USER_NAME}
WorkingDirectory=${PROJECT_DIR}
ExecStart=/snap/bin/cargo run --features sqlite --release
Restart=always
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
EOL

# Recharger le daemon systemd
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

# Activer le service pour qu'il démarre au démarrage
echo "Enabling ${SERVICE_NAME} service to start on boot..."
sudo systemctl enable ${SERVICE_NAME}.service

# Démarrer le service
echo "Starting ${SERVICE_NAME} service..."
sudo systemctl start ${SERVICE_NAME}.service

# Vérifier l'état du service
echo "Checking the status of ${SERVICE_NAME} service..."
sudo systemctl status ${SERVICE_NAME}.service

