#!/bin/bash

# Mettre à jour et installer Apache2
sudo apt update
sudo apt install -y apache2

# Installer ModSecurity
sudo apt install -y libapache2-mod-security2

# Installer les règles OWASP CRS
sudo apt install -y modsecurity-crs

# Vérifier si le répertoire /etc/modsecurity existe, sinon le créer
sudo mkdir -p /etc/modsecurity

# Activer ModSecurity
sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

# Inclure les règles OWASP CRS dans la configuration de sécurité Apache
rm /etc/apache2/mods-enabled/security2.conf

echo "
LoadModule unique_id_module modules/mod_unique_id.so
LoadModule security2_module modules/mod_security2.so

<IfModule security2_module>

        Include /etc/modsecurity/crs/crs-setup.conf
        Include /usr/share/modsecurity-crs/rules/*.conf

</IfModule>
" | sudo tee -a /etc/apache2/mods-enabled/security2.conf

# Créer un répertoire pour les certificats SSL
sudo mkdir -p /etc/apache2/ssl

# Générer un certificat auto-signé
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/apache2/ssl/apache-selfsigned.key -out /etc/apache2/ssl/apache-selfsigned.crt -subj "/C=US/ST=State/L=City/O=Organization/OU=Department/CN=example.com"

# Configurer le reverse proxy
echo "
<VirtualHost *:443>
    ServerAdmin webmaster@localhost

    SSLEngine on
    SSLCertificateFile /etc/apache2/ssl/apache-selfsigned.crt
    SSLCertificateKeyFile /etc/apache2/ssl/apache-selfsigned.key

    ProxyPreserveHost On
    ProxyPass / http://localhost:8000/
    ProxyPassReverse / http://localhost:8000/

    <Proxy *>
        Order allow,deny
        Allow from all
    </Proxy>

    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined

    <IfModule security2_module>
        SecRuleEngine On
        Include /etc/modsecurity/crs/crs-setup.conf
        Include /usr/share/modsecurity-crs/rules/*.conf
    </IfModule>

</VirtualHost>
" | sudo tee /etc/apache2/sites-available/reverse-proxy.conf

# Activer les modules et le site
sudo a2enmod ssl
sudo a2enmod proxy
sudo a2enmod proxy_http
sudo a2enmod headers
sudo a2enmod security2
sudo a2ensite reverse-proxy.conf

# Vérifier la configuration
sudo apache2ctl configtest

# Redémarrer Apache2
sudo systemctl restart apache2

echo "Configuration terminée. Le reverse proxy est maintenant opérationnel."
