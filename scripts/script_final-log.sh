# ================================================= #
# This script will write the next informations list:
# - System version
# - Storage available
# - Ip address
# - Users list
# - All apps installed
# - Cpu, cores and RAM 
# - Open ports
# - firewall status
# ================================================= #

dir = /tmp/final-log.txt

# UNIX system version check
echo "System version" > $dir
echo uname -all >> $dir
echo "" >> $dir

# Storage available check
echo "Storage available:" >> $dir
echo df -h >> $dir
echo "" >> $dir

# Ip address
echo "IP Address info:" >> $dir
echo ip a >> $dir
echo "" >> $dir

# Users list
echo "Users list:" >> $dir
echo cut -d: -f1 /etc/passwd >> $dir
echo "" >> $dir

# All apps installed
echo "Apps and packages installed:" >> $dir
echo sudo apt list --installed | less >> $dir
echo "" >> $dir

# CPU type, cores and RAM
echo "CPU: " >> $dir
echo sudo lshw - class CPU >> $dir
echo "" >> $dir
# Check for RAM command line

# Open ports
echo "Open ports:" >> $dir
echo sudo netstat -tulnp >> $dir
echo "" >> $dir

# Firewall status
# echo "Firewall status" >> $dir
#echo status awf >> $dir
