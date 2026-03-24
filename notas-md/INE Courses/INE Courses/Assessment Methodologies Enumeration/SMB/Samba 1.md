# Samba 1

# enumerate

```
root@attackdefense:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: ip_vti0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN group default qlen 1000
    link/ipip 0.0.0.0 brd 0.0.0.0
145172: eth0@if145173: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:0a:01:00:03 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.1.0.3/16 brd 10.1.255.255 scope global eth0
       valid_lft forever preferred_lft forever
145175: eth1@if145176: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:c0:81:d9:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.129.217.2/24 brd 192.129.217.255 scope global eth1
       valid_lft forever preferred_lft forever
root@attackdefense:~# nmap 192.129.217.0/24
Starting Nmap 7.70 ( https://nmap.org ) at 2023-11-23 22:25 UTC
Nmap scan report for client-192-129-217-1.hostwindsdns.com (192.129.217.1)
Host is up (0.000013s latency).
Not shown: 997 closed ports
PORT    STATE    SERVICE
22/tcp  open     ssh
80/tcp  filtered http
443/tcp filtered https
MAC Address: 02:42:A6:4C:75:62 (Unknown)

Nmap scan report for target-1 (192.129.217.3)
Host is up (0.0000090s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:81:D9:03 (Unknown)

Nmap scan report for attackdefense.com (192.129.217.2)
Host is up (0.0000040s latency).
All 1000 scanned ports on attackdefense.com (192.129.217.2) are closed

Nmap done: 256 IP addresses (3 hosts up) scanned in 3.40 seconds
```

# More enumeration (udp)

```
root@attackdefense:~# nmap 192.129.217.3 -sU --top-port 25 -sV 
Starting Nmap 7.70 ( https://nmap.org ) at 2023-11-23 22:27 UTC
Stats: 0:01:37 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 22:30 (0:01:17 remaining)
Nmap scan report for target-1 (192.129.217.3)
Host is up (0.000064s latency).

PORT      STATE         SERVICE      VERSION
53/udp    closed        domain
67/udp    closed        dhcps
68/udp    closed        dhcpc
69/udp    closed        tftp
111/udp   closed        rpcbind
123/udp   closed        ntp
135/udp   closed        msrpc
137/udp   open          netbios-ns   Samba nmbd netbios-ns (workgroup: RECONLABS)
138/udp   open|filtered netbios-dgm
139/udp   closed        netbios-ssn
161/udp   closed        snmp
162/udp   closed        snmptrap
445/udp   closed        microsoft-ds
500/udp   closed        isakmp
514/udp   closed        syslog
520/udp   closed        route
631/udp   closed        ipp
998/udp   closed        puparp
1434/udp  closed        ms-sql-m
1701/udp  closed        L2TP
1900/udp  closed        upnp
4500/udp  closed        nat-t-ike
5353/udp  closed        zeroconf
49152/udp closed        unknown
49154/udp closed        unknown
MAC Address: 02:42:C0:81:D9:03 (Unknown)
Service Info: Host: SAMBA-RECON

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 118.28 seconds
```

# smb-os-discovery

```
root@attackdefense:~# nmap 192.129.217.3 -p445 --script smb-os-discovery
Starting Nmap 7.70 ( https://nmap.org ) at 2023-11-23 22:30 UTC
Nmap scan report for target-1 (192.129.217.3)
Host is up (0.000067s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:81:D9:03 (Unknown)

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.3.11-Ubuntu)
|   Computer name: victim-1
|   NetBIOS computer name: SAMBA-RECON\x00
|   Domain name: \x00
|   FQDN: victim-1
|_  System time: 2023-11-23T22:30:24+00:00

Nmap done: 1 IP address (1 host up) scanned in 0.36 seconds
```

Here is the flag 👆 it is the NetBIOS computer name.

# other useful commands

Metasploit

```
msfconsole
...
msf5 > use auxiliary/scanner/smb/smb_version
msf5 auxiliary(scanner/smb/smb_version) > set RHOSTS 192.129.217.3
RHOSTS => 192.129.217.3
msf5 auxiliary(scanner/smb/smb_version) > exploit
[*] 192.129.217.3:445     - Host could not be identified: Windows 6.1 (Samba 4.3.11-Ubuntu)
[*] 192.129.217.3:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

smbclient

```
root@attackdefense:~# smbclient -L 192.129.217.3 -N

        Sharename       Type      Comment
        ---------       ----      -------
        public          Disk      
        john            Disk      
        aisha           Disk      
        emma            Disk      
        everyone        Disk      
        IPC$            IPC       IPC Service (samba.recon.lab)
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        RECONLABS            SAMBA-RECON
```

rpcclient

```
root@attackdefense:~# rpcclient -U "" -N 192.129.217.3
rpcclient $>
```
