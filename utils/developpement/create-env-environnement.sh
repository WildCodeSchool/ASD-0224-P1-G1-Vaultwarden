#! /bin/bash
workspace="/home/workspace"

mkdir -p $workspace
cd $workspace
cp /etc/ssh/sshd_config $workspace/sshd_config_bakcup
cp /etc/ssh/ssh_config $workspace/ssh_config_bakcup

touch reset_script.sh
cat <<EOF > reset_script.sh
#! /bin/bash
cp $workspace/sshd_config_bakcup /etc/ssh/sshd_config 
cp $workspace/ssh_config_bakcup /etc/ssh/ssh_config 
EOF


