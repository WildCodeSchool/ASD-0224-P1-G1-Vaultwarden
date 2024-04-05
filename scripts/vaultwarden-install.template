#!/bin/bash

apt update
apt upgrade -y

#Docker install
apt install -y ca-certificates curl
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc 
chmod a+r /etc/apt/keyrings/docker.asc
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
apt update
apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

#Node JS 16.x Install
curl -s https://deb.nodesource.com/setup_16.x | sudo bash
apt update
apt install -y nodejs

#Rocket install
apt install -y pkg-config openssl-sys libssl-dev libmariadb-dev-compat libmariadb-dev 

snap install rustup

rustup default stable --classic

cargo run --features sqlite --release

#Docker uninstall
apt purge -y docker*
apt autoremove -y