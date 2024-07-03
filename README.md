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

## How use the project


#### Information 
In the hardening file the default SSH connexion Port will be set to 1754 with an variable. That variable can be modified.
Please take note of that, before run the script. To adapt your future connexions and other scripts using SSH. Notify other peoples.
Or set the port in the script to your current Port 
PORT=1754

## Developpement 
### Hardening part
In the hardening scripts, there is a section that can be commented out to facilitate easier development with syntax highlighting in Visual Studio Code.
When you are developing, you can comment out the "REMOTE_COMMANDS" block at the top and at the bottom of the script. This allows you to leverage the full syntax highlighting and code editing features of your IDE.
Do ctrl + f "REMOTE_COMMANDS" to find them
# Automating deployment and installation of Vaultwarden
