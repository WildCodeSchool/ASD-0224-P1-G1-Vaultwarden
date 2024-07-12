# ASD-0224-P1-G1-Vaultwarden
ASD SESSION 2024 02, projet 1, installation automatisée vaultwarden

## What is Vaultwarden ? 

Vaultwarden is an alternative server implementation of Bitwarden.
Vaultwarden is an excellent open-source password manager. Your Vaultwarden server can be used as your primary password manager on your phone, 
web browser, and desktop. For privacy-focused tech-savvy individuals, it would only make sense to add it to your stack. 
Hackers aren't likely to target people who don't seem worth the effort, and if everyone had their own self-hosted password manager it would 
be even more of a headache to hack anything at all! This is unrealistic of course, but hosting your own Vaultwarden and getting off of big 
providers is a good way to go to keep your passwords safe.

## Goal
The objective of the project is to automate the installation process of Vaultwarden to a server.

## How to use the project
To use the project, you need to be the admin for sudo commands and Ubuntu (not everything may work on debian) and clone this repo with the "git clone" command.

#### Information 
In the hardening file, the default SSH connection port will be set to 1754 using a variable. Or set the port in the script to your current Port.
We advise choosing an SSH port above 1000 because some port scan scripts do not scan ports over 1000. Port 1754 has been chosen for this reason.After remember to note the new SSH port.

Please take note of that, before run the script. To adapt your future connexions and other scripts using SSH. Notify other peoples.

PORT=1754

## Developpement 
### Hardening part
In the hardening scripts, there is a section that can be commented out to facilitate easier development with syntax highlighting in Visual Studio Code.
When you are developing, you can comment out the "REMOTE_COMMANDS" block at the top and at the bottom of the script. This allows you to leverage the full syntax highlighting and code editing features of your IDE.
Do ctrl + f "REMOTE_COMMANDS" to find them

## Automating deployment and installation of Vaultwarden

## Application hardening
The choosen solution for software hardening is ModSecurity.
The WAF is installed as a module for Apache.

To help further the filtering, OWASP rulesets have been implemented.
List of enabled rules can be found in :
- /usr/share/modsecurity-crs/rules/*.conf
- /etc/modsecurity/crs/crs-setup.conf

With these filters enabled, the apache service is setup as a proxy and will play it's role as a WAF.