#! /bin/bash
workspace="/home/workspace"

apt install openssh-client
apt install openssh-server


mkdir -p $workspace
cd $workspace
cp /etc/ssh/sshd_config $workspace/sshd_config_bakcup
cp /etc/ssh/ssh_config $workspace/ssh_config_bakcup

touch reset_script.sh
touch developpement-script.sh

cat <<EOF > reset_script.sh
#! /bin/bash
cp $workspace/sshd_config_bakcup /etc/ssh/sshd_config 
cp $workspace/ssh_config_bakcup /etc/ssh/ssh_config 
EOF

chmod +x reset_script.sh
chmod +x developpement-script.sh

touch show_ssh_files.sh 
cat <<EOF > show_ssh_files.sh 
#! /bin/bash
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_config
EOF

chmod +x show_ssh_files.sh