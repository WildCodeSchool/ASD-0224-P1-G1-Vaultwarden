#!/bin/bash
# ================================================= #
# This script will write the next information list into a .log file:
# - System version
# - Storage available
# - Ip address
# - Users list
# - All apps installed
# - Cpu, cores and RAM 
# - Open ports
# - Firewall status
# ================================================= #

dir="/tmp/install_log.txt"
space=echo "" >> "$dir"

apt install netstat

# UNIX system version check
echo "System version:" >> "$dir"
uname -a >> "$dir"
$space

# Storage available check
echo "Storage available:" >> "$dir"
df -h >> "$dir"
$space

# Ip address
echo "IP Address info:" >> "$dir"
ip a >> "$dir"
$space

# Users list
echo "Users list:" >> "$dir"
cut -d: -f1 /etc/passwd >> "$dir"
$space

# All apps installed
echo "Apps and packages installed:" >> "$dir"
sudo apt list --installed >> "$dir"
$space

# CPU type, cores and RAM
echo "CPU: " >> "$dir"
sudo lshw -class CPU >> "$dir"
$space
# Check for RAM command line
echo "RAM:" >> "$dir"
free -h >> "$dir"
$space

# Open ports
echo "Open ports:" >> "$dir"
sudo netstat -tulnp >> "$dir"
$space

# Firewall status
echo "Firewall status" >> "$dir"
sudo ufw status >> "$dir"
