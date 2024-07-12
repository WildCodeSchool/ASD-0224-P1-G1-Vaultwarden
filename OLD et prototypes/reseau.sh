#/bin/bash

ip link set dev ens19 up
ip -6 addr add 2a01:4f8:141:53ea::1834/64 dev ens19
ip -6 route add default via 2a01:4f8:141:53ea::2 dev ens19