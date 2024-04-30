#!/bin/bash

# L administrateur doit connaitre et renseigner le mdp root pour lancer l installation

# Mise à jour sys et app 
echo "Mise à jour système et des applications en cours, veuillez taper le mot de passe super utilisateur"
sudo apt update && sudo apt upgrade -y  
if [ $? -ne 0 ]; then
    echo "Echec de la mise à jour. Veuillez vérifier le message d'erreur"
fi
echo "Mise à jour terminée."

# Installation des applications

echo "Les applications nécessaires au fonctionnement de VaultWarden."

# Installation de build-essential
echo "Installation de build-essential en cours..."
sudo apt install -qq build-essential
if [ $? -ne 0 ]; then
    echo "Echec de l'installation. Veuillez vérifier le message d'erreur"
fi
echo "Installation terminée."

# Installation de curl
echo "Installation de curl en cours..."
sudo apt install -qq curl
if [ $? -ne 0 ]; then
    echo "Echec de l'installation. Veuillez vérifier le message d'erreur"
fi
echo "Installation terminée."

# Installation de git
echo "Installation de git en cours..."
sudo apt install -qq git 
if [ $? -ne 0 ]; then
    echo "Echec de l'installation. Veuillez vérifier le message d'erreur"
fi
echo "Installation terminée."

# Installation de nginx pour reverse-proxy

sudo apt install -qq nginx 
if [ $? -ne 0 ]; then
    echo "Echec de l'installation. Veuillez vérifier le message d'erreur"
fi
echo "Installation terminée."

# Installation des librairies nécessaires au fonctionnement de Vaultwarden
echo "Installation des librairies nécessaires au fonctionnement de Vaultwarden"
sudo apt install -qq libssl-dev libsqlite3-dev libmariadb libmariadb-dev-compat libpq-dev
if [ $? -ne 0 ]; then
    echo "Echec de l'installation. Veuillez vérifier le/s message/s d'erreur"
fi
echo "Installation terminée."

sudo curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
#nvm use 16
#npm install -g 8.11
npm install

# Vérification de l'installation de Node.js
echo "Vérification de l'installation de Node.js..."
node --version
npm --version

# log des install faites avec apt il faudrait peut être voir pour l'exploiter, pour l'instant je n'ai pas trouvé mieux
# nano /var/log/apt/history.log