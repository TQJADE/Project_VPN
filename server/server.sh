sudo ip addr add 10.0.4.1/24 dev tun0
sudo ifconfig tun0 up

sudo route add -net 10.0.5.0 netmask 255.255.255.0 dev tun0
sudo sysctl net.ipv4.ip_forward=1
sudo route add -net 10.0.20.0 netmask 255.255.255.0 gw 10.0.10.1
sudo route add -net 10.0.20.0 netmask 255.255.255.0 dev tun0
