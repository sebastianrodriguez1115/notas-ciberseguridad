# IP commands

```
┌──(kali㉿kali)-[~]
└─$ ip addr
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:11:1d:c8 brd ff:ff:ff:ff:ff:ff
    inet 192.168.20.31/24 brd 192.168.20.255 scope global dynamic noprefixroute eth0
       valid_lft 859873sec preferred_lft 859873sec
    inet6 2800:484:777b:9100:8734:ae4f:bc0f:fb66/64 scope global dynamic noprefixroute
       valid_lft 908195sec preferred_lft 303395sec
    inet6 fe80::4bc7:6e98:e75d:a48a/64 scope link noprefixroute
       valid_lft forever preferred_lft forever

┌──(kali㉿kali)-[~]
└─$ ip n
192.168.20.1 dev eth0 lladdr 14:82:5b:00:00:20 STALE
fe80::1682:5bff:fe00:20 dev eth0 lladdr 14:82:5b:00:00:20 router STALE

┌──(kali㉿kali)-[~]
└─$ arp -a

? (192.168.20.1) at 14:82:5b:00:00:20 [ether] on eth0

┌──(kali㉿kali)-[~]
└─$ ip route
default via 192.168.20.1 dev eth0 proto dhcp src 192.168.20.31 metric 100
192.168.20.0/24 dev eth0 proto kernel scope link src 192.168.20.31 metric 100

┌──(kali㉿kali)-[~]
└─$ route
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         192.168.20.1    0.0.0.0         UG    100    0        0 eth0
192.168.20.0    0.0.0.0         255.255.255.0   U     100    0        0 eth0
```
