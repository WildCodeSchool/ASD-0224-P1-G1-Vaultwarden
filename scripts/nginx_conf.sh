#!/bin/bash

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit
fi

# Variables
nginx_conf="/etc/nginx/sites-available/default"
apache_port_conf="/etc/apache2/ports.conf"
apache_vaultwarden="/etc/apache2/route/vers/vaultwarden"
domaine="notre.domaine.v6.rocks"  # Replace with our domaine

# Update package lists
echo "Updating package lists..."
apt update

# Install Nginx and Apache if not already installed
echo "Installing Nginx ..."
apt install -y nginx

# Configure Nginx
echo "Configuring Nginx as a reverse proxy..."
cat > "$nginx_conf" <<EOF
server {
    listen 80;
    server_name $domaine;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Configure Apache to listen on port 8080
echo "Configuring Apache to listen on port 8080..."
sed -i 's/Listen 80/Listen 8080/' "$apache_port_conf"

# Update Apache Virtual Host to use port 8080
echo "Updating Apache Virtual Host configuration..."
sed -i 's/<VirtualHost \*:80>/<VirtualHost \*:8080>/' "$apache_vaultwarden"

# Restart services
echo "Restarting Nginx and Apache services..."
systemctl restart nginx
systemctl restart apache2

echo "Nginx as a reverse proxy to Apache is now set up."
