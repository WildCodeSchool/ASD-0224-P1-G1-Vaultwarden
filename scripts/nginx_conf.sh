#!/bin/bash
#-------------------------------
# TODO
# ------------------------------
# apt-get install -qq -o=Dpkg::Use-Pty=0 <packages>
# Use the above command to make the packages install silent

# Declaration variables pour logging
dir="/tmp/install_log.txt"
install_date="$(date +'%Y_%m_%d')"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit
fi

# Variables
nginx_conf="/etc/nginx/sites-available/default"
domaine="notre.domaine.v6.rocks"  # Replace with our domaine
dynv6_token="" # Penser a resegner notre token

# Update package lists
echo "Updating package lists..."
apt update

# Install Nginx if not already installed
echo "Installing Nginx ..."
apt install -qqy apt-utils autoconf automake libcurl4-openssl-dev libgeoip-dev liblmdb-dev libpcre++-dev libtool libxml2-dev libyajl-dev pkgconf wget zlib1g-dev certbot
echo -e "$install_date - Installation des packages pour Nginx et Modprobe realisee.\n" >> $dir

# Mise en pause de Nginx pendant leur configuration / Stop Nginx and Apache2 before installing and setting up the config for modsecurity
systemctl stop nginx

##################################
########### Certbot  WIP ##############
##################################
certbot certonly --manual --register-unsafely-without-email --preferred-challenges dns -d "*.$domaine" -d $domaine
echo -e "$install_date - Certificat recupere.\n" >> $dir
echo -e "\n" && read -p "\nFin install Certbot\n" && echo -e "\n"

# Configure Nginx
echo "Configuring Nginx as a reverse proxy..."
cat > "$nginx_conf" <<EOF
server {
    listen 80;
    server_name $domaine;

    access_log /var/log/nginx/access.log;
    
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
echo -e "$install_date - Parametrage Nginx reverse proxy et preparation Modprobe.\n" >> $dir
echo -e "\n" && read -p "\nFin modif conf Nginx\n" && echo -e "\n"

# Recuperation et installation de ModSecurity
rm -rf /usr/local/src/ModSecurity/
git clone --depth 1 -b v3/master --single-branch https://github.com/SpiderLabs/ModSecurity /usr/local/src/ModSecurity
cd /usr/local/src/ModSecurity/
git submodule init
git submodule update --remote
echo -e "\n" && read -p "\nFin recup git Modsecurity\n" && echo -e "\n"
./build.sh
echo -e "\n" && read -p "\nFin build.sh Modsecurity\n" && echo -e "\n"
./configure
echo -e "\n" && read -p "\nFin configure.sh Modsecurity\n" && echo -e "\n"
make
echo -e "\n" && read -p "\nFin make Modsecurity\n" && echo -e "\n"
make install
echo -e "\n" && read -p "\nFin make install Modsecurity\n" && echo -e "\n"

# Module ModSecurity pour Nginx
rm -rf /usr/local/src/ModSecurity-nginx
git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git /usr/local/src/ModSecurity-nginx
cd /usr/local/src/ModSecurity-nginx
echo -e "\n" && read -p "\nFin git clone Modsecurity-nginx\n" && echo -e "\n"
nginx_vers=$(nginx -v 2>&1 | awk -F'/' '{print $2}' | awk -F' ' '{print $1}')
wget http://nginx.org/download/nginx-$nginx_vers.tar.gz
tar zxvf nginx-$nginx_vers.tar.gz
cd nginx-$nginx_vers/
./configure --with-compat --add-dynamic-module=../ModSecurity-nginx
make modules
echo -e "\n" && read -p "\nFin make module Modsecurity-nginx\n" && echo -e "\n"
cp /usr/local/src/ModSecurity-nginx/nginx-$nginx_vers/objs/ngx_http_modsecurity_module.so /etc/nginx/modules/
echo -e "$install_date - Recuperation et compilation de Modprobe OK.\n" >> $dir
echo -e "\n" && read -p "\nFin copie Modsecurity-nginx dans modules Nginx\n" && echo -e "\n"

# Ajout du load module a la conf Nginx
sed -i '/include \/etc\/nginx\/modules-enabled\/\*\.conf;/a load_module \/etc\/nginx\/modules\/ngx_http_modsecurity_module.so;' /etc/nginx/nginx.conf

# Configuration ModSecurity
mkdir /etc/nginx/modsec
wget -P /etc/nginx/modsec/ https://raw.githubusercontent.com/SpiderLabs/ModSecurity/v3/master/modsecurity.conf-recommended
mv /etc/nginx/modsec/modsecurity.conf-recommended /etc/nginx/modsec/modsecurity.conf
cp /usr/local/src/ModSecurity/unicode.mapping /etc/nginx/modsec/
echo -e "\n" && read -p "\nRecuperation de la conf recomended\n" && echo -e "\n"

sed -i 's/DetectionOnly/On/' /etc/nginx/modsec/modsecurity.conf
echo -e "\n" && read -p "\nModif config modsecurity\n" && echo -e "\n"

echo -e "Include \"/etc/nginx/modsec/modsecurity.conf\"" > /etc/nginx/modsec/main.conf

# OWASP Ruleset v3.2
cd /usr/local/src
wget https://github.com/SpiderLabs/owasp-modsecurity-crs/archive/refs/tags/v3.2.0.tar.gz
tar -xzvf v3.2.0.tar.gz
echo -e "\n" && read -p "\nRecuperation et decompression regles OWASP\n" && echo -e "\n"

cd owasp-modsecurity-crs-3.2.0/
cp crs-setup.conf.example crs-setup.conf
echo -e "$install_date - Application des regles de securite de base OWASP.\n" >> $dir
echo -e "\n" && read -p "\nCopie regles OWASP\n" && echo -e "\n"

#################################################################
##### choix du site a surveiller/ liste d esceptions ajouter ####
#################################################################

# Restart services and enable Nginx
echo "Restarting Nginx service..."
systemctl enable nginx
systemctl restart nginx

echo "Nginx as a reverse proxy to Apache is now set up."
