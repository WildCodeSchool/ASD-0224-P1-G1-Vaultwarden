#!/bin/bash

# Vérifier si l'utilisateur a les privilèges root
if [ "$EUID" -ne 0 ]; then
    echo "Veuillez exécuter ce script avec les privilèges root."
    exit 1
fi

# Mettre à jour la liste des paquets et installer Nginx
echo "Mise à jour des paquets et installation de Nginx..."
apt update
apt install -y nginx

# Demander le nom de domaine pour le certificat SSL
read -p "Entrez votre nom de domaine (ex: exemple.com): " DOMAIN

# Demander si un certificat SSL auto-signé doit être créé
read -p "Voulez-vous créer un certificat SSL auto-signé? (y/n): " CREATE_CERT

if [ "$CREATE_CERT" == "y" ]; then
    echo "Création du certificat SSL auto-signé pour $DOMAIN..."
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt -subj "/CN=$DOMAIN"
    SSL_CONF="
    listen 443 ssl;
    ssl_certificate /etc/nginx/ssl/nginx.crt;
    ssl_certificate_key /etc/nginx/ssl/nginx.key;
    "
else
    SSL_CONF="
    listen 443;
    "
fi

# Créer un fichier de configuration Nginx pour le reverse proxy
PROXY_CONF="/etc/nginx/sites-available/reverse-proxy"

echo "Création de la configuration Nginx pour le reverse proxy..."
cat > $PROXY_CONF <<EOL
server {
    listen 80;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}

server {
    $SSL_CONF
    server_name $DOMAIN;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOL

# Créer un lien symbolique pour activer le site
echo "Activation du site en créant un lien symbolique..."
ln -s $PROXY_CONF /etc/nginx/sites-enabled/

# Tester la configuration de Nginx
echo "Test de la configuration Nginx..."
nginx -t

# Redémarrer Nginx pour appliquer les changements
echo "Redémarrage de Nginx..."
systemctl restart nginx

# Vérifier l'état de Nginx
echo "Vérification de l'état de Nginx..."
systemctl status nginx

echo "Configuration du reverse proxy Nginx terminée."
