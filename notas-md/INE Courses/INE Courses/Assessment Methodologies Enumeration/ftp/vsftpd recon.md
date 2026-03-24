# vsftpd recon

# nmap enum

```
root@attackdefense:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: ip_vti0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN group default qlen 1000
    link/ipip 0.0.0.0 brd 0.0.0.0
146294: eth0@if146295: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:0a:01:00:09 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.1.0.9/16 brd 10.1.255.255 scope global eth0
       valid_lft forever preferred_lft forever
146297: eth1@if146298: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:c0:ea:53:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.234.83.2/24 brd 192.234.83.255 scope global eth1
       valid_lft forever preferred_lft forever

root@attackdefense:~# nmap -sV 192.234.83.3 --script ftp-anon
Starting Nmap 7.70 ( https://nmap.org ) at 2023-11-25 16:30 UTC
Nmap scan report for target-1 (192.234.83.3)
Host is up (0.0000090s latency).
Not shown: 999 closed ports
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-r--r--    1 ftp      ftp            33 Dec 18  2018 flag
|_drwxr-xr-x    2 ftp      ftp          4096 Dec 18  2018 pub
MAC Address: 02:42:C0:EA:53:03 (Unknown)
Service Info: OS: Unix

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.51 seconds
```

# Get flag

```
root@attackdefense:~# ftp 192.234.83.3
Connected to 192.234.83.3.
220 (vsFTPd 3.0.3)
Name (192.234.83.3:root): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp            33 Dec 18  2018 flag
drwxr-xr-x    2 ftp      ftp          4096 Dec 18  2018 pub
226 Directory send OK.
ftp> get flag
local: flag remote: flag
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for flag (33 bytes).
226 Transfer complete.
33 bytes received in 0.00 secs (109.2426 kB/s)
ftp> exit
221 Goodbye.
root@attackdefense:~# cat flag
4267bdfbff77d7c2635e4572519a8b9c
```
