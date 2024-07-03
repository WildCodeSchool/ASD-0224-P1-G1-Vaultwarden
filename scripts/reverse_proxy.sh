#!/bin/bash

# Définir le domaine et l'email pour Let's Encrypt
DOMAIN="yourdomain.com"
EMAIL="your-email@example.com"

# Vérifier si le domaine et l'email sont fournis
if [ -z "$DOMAIN" ]; then
    echo "Please provide your domain name"
    exit 1
fi

if [ -z "$EMAIL" ]; then
    echo "Please provide your email address"
    exit 1
fi

# Mettre à jour les paquets et installer Nginx
sudo apt update
sudo apt install -y nginx

# Installer Certbot et le plugin Nginx pour Let's Encrypt
sudo apt install -y certbot python3-certbot-nginx

# Obtenir un certificat SSL avec Certbot
sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m $EMAIL

# Créer une configuration Nginx pour le domaine
NGINX_CONF="/etc/nginx/sites-available/$DOMAIN"

cat <<EOF | sudo tee $NGINX_CONF
server {
    listen 80;
    server_name $DOMAIN;

    # Redirection de HTTP vers HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass http://localhost:8000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Activer la configuration en créant un lien symbolique dans le dossier sites-enabled
sudo ln -s $NGINX_CONF /etc/nginx/sites-enabled/

# Vérifier la configuration de Nginx
sudo nginx -t

# Recharger Nginx pour appliquer les modifications
sudo systemctl reload nginx

echo "Nginx has been configured as a reverse proxy with HTTPS for $DOMAIN"
