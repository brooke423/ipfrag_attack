#/bin/sh

if [ "$1" == "" ] ; then
    iptables -I OUTPUT 1 --protocol tcp --tcp-flags RST RST -d 10.68.46.112 -j DROP --out-interface eth0
    iptables -I OUTPUT 1 --protocol icmp -d 10.68.46.112 -j DROP --out-interface eth0
    iptables -A OUTPUT -j ACCEPT
else
    echo iptables -F
    iptables -F
fi

