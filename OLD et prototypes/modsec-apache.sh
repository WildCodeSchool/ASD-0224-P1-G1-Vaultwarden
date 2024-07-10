#!/bin/bash

# Maj du temps (en cas de snapshot)
systemctl restart systemd-timesyncd

# Installation et activation module modsecurity sur apache
systemctl stop apache2
apt install apache2 libapache2-mod-security2 git -y
a2enmod headers
a2enmod security2

# Config modsec
cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

# Regles OWASP
rm -rf /usr/share/modsecurity-crs
git clone https://github.com/coreruleset/coreruleset /usr/share/modsecurity-crs
mv /usr/share/modsecurity-crs/crs-setup.conf.example /usr/share/modsecurity-crs/crs-setup.conf
mv /usr/share/modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example /usr/share/modsecurity-crs/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf

echo -e "<IfModule security2_module>" > /etc/apache2/mods-available/security2.conf
echo -e "\tSecDataDir /var/cache/modsecurity" >> /etc/apache2/mods-available/security2.conf
echo -e "\tInclude /usr/share/modsecurity-crs/crs-setup.conf" >> /etc/apache2/mods-available/security2.conf
echo -e "\tInclude /usr/share/modsecurity-crs/rules/*.conf" >> /etc/apache2/mods-available/security2.conf
echo -e "</IfModule>" >> /etc/apache2/mods-available/security2.conf

## SecRuleEngine On >> dans virtual host ##

# Redemarrage final d apache
systemctl restart apache2