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

dir="/tmp/final-log.txt"

# UNIX system version check
echo "System version:" > "$dir"
uname -a >> "$dir"
echo "" >> "$dir"

# Storage available check
echo "Storage available:" >> "$dir"
df -h >> "$dir"
echo "" >> "$dir"

# Ip address
echo "IP Address info:" >> "$dir"
ip a >> "$dir"
echo "" >> "$dir"

# Users list
echo "Users list:" >> "$dir"
cut -d: -f1 /etc/passwd >> "$dir"
echo "" >> "$dir"

# All apps installed
echo "Apps and packages installed:" >> "$dir"
sudo apt list --installed >> "$dir"
echo "" >> "$dir"

# CPU type, cores and RAM
echo "CPU: " >> "$dir"
sudo lshw -class CPU >> "$dir"
echo "" >> "$dir"
# Check for RAM command line
echo "RAM:" >> "$dir"
free -h >> "$dir"
echo "" >> "$dir"

# Open ports
echo "Open ports:" >> "$dir"
sudo netstat -tulnp >> "$dir"
echo "" >> "$dir"

# Firewall status
echo "Firewall status" >> "$dir"
sudo ufw status >> "$dir"
