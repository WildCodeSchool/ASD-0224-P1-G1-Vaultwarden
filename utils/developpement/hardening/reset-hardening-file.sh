#! /bin/bash

### File created to help to test the hardening script in a container 
echo "That will create temporary variables to test some bash scripts in a virtualized environnement"
read -p "What is the filename that you want to use ? " bash_filename
alias reset="echo ' ' > $bash_filename" 
alias ex="./$bash_filename"
alias edit="nano $bash_filename"
alias checkscript="bash -n $bash_filename"