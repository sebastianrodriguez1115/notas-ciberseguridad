# Samba 3

nmap enum

```
root@attackdefense:~# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: ip_vti0@NONE: <NOARP> mtu 1480 qdisc noop state DOWN group default qlen 1000
    link/ipip 0.0.0.0 brd 0.0.0.0
145594: eth0@if145595: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:0a:01:00:05 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 10.1.0.5/16 brd 10.1.255.255 scope global eth0
       valid_lft forever preferred_lft forever
145597: eth1@if145598: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:c0:86:82:02 brd ff:ff:ff:ff:ff:ff link-netnsid 0
    inet 192.134.130.2/24 brd 192.134.130.255 scope global eth1
       valid_lft forever preferred_lft forever
root@attackdefense:~# nmap 192.134.130.2/24
Starting Nmap 7.70 ( https://nmap.org ) at 2023-11-24 17:24 UTC
Nmap scan report for risette.esgt.cnam.fr (192.134.130.1)
Host is up (0.0000070s latency).
Not shown: 997 closed ports
PORT    STATE    SERVICE
22/tcp  open     ssh
80/tcp  filtered http
443/tcp filtered https
MAC Address: 02:42:60:E8:D4:A4 (Unknown)

Nmap scan report for target-1 (192.134.130.3)
Host is up (0.0000090s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:86:82:03 (Unknown)

Nmap scan report for attackdefense.com (192.134.130.2)
Host is up (0.0000040s latency).
All 1000 scanned ports on attackdefense.com (192.134.130.2) are closed

Nmap done: 256 IP addresses (3 hosts up) scanned in 3.42 seconds
root@attackdefense:~# nmap 192.134.130.3 -p445 --script smb-enum-shares
Starting Nmap 7.70 ( https://nmap.org ) at 2023-11-24 17:25 UTC
Nmap scan report for target-1 (192.134.130.3)
Host is up (0.000050s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:86:82:03 (Unknown)

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\192.134.130.3\IPC$: 
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (samba.recon.lab)
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\192.134.130.3\aisha: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\samba\aisha
|     Anonymous access: <none>
|     Current user access: <none>
|   \\192.134.130.3\emma: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\samba\emma
|     Anonymous access: <none>
|     Current user access: <none>
|   \\192.134.130.3\everyone: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\samba\everyone
|     Anonymous access: <none>
|     Current user access: <none>
|   \\192.134.130.3\john: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\samba\john
|     Anonymous access: <none>
|     Current user access: <none>
|   \\192.134.130.3\public: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\samba\public
|     Anonymous access: READ/WRITE
|_    Current user access: READ/WRITE

Nmap done: 1 IP address (1 host up) scanned in 0.72 seconds
```

enum4linux

```
root@attackdefense:~# enum4linux -S 192.134.130.3   
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Nov 24 17:27:30 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.134.130.3
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

 ===================================================== 
|    Enumerating Workgroup/Domain on 192.134.130.3    |
 ===================================================== 
[+] Got domain/workgroup name: RECONLABS

 ====================================== 
|    Session Check on 192.134.130.3    |
 ====================================== 
[+] Server 192.134.130.3 allows sessions using username '', password ''

 ============================================ 
|    Getting domain SID for 192.134.130.3    |
 ============================================ 
Domain Name: RECONLABS
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ========================================== 
|    Share Enumeration on 192.134.130.3    |
 ========================================== 

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

[+] Attempting to map shares on 192.134.130.3
//192.134.130.3/public  Mapping: OK, Listing: OK
//192.134.130.3/john    Mapping: DENIED, Listing: N/A
//192.134.130.3/aisha   Mapping: DENIED, Listing: N/A
//192.134.130.3/emma    Mapping: DENIED, Listing: N/A
//192.134.130.3/everyone        Mapping: DENIED, Listing: N/A
//192.134.130.3/IPC$    [E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*
enum4linux complete on Fri Nov 24 17:27:31 2023

root@attackdefense:~# enum4linux -G 192.134.130.3
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Nov 24 17:28:49 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.134.130.3
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

 ===================================================== 
|    Enumerating Workgroup/Domain on 192.134.130.3    |
 ===================================================== 
[+] Got domain/workgroup name: RECONLABS

 ====================================== 
|    Session Check on 192.134.130.3    |
 ====================================== 
[+] Server 192.134.130.3 allows sessions using username '', password ''

 ============================================ 
|    Getting domain SID for 192.134.130.3    |
 ============================================ 
Domain Name: RECONLABS
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 =============================== 
|    Groups on 192.134.130.3    |
 =============================== 

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:
group:[Testing] rid:[0x3f0]

[+] Getting local group memberships:

[+] Getting domain groups:
group:[Maintainer] rid:[0x3ee]
group:[Reserved] rid:[0x3ef]

[+] Getting domain group memberships:
enum4linux complete on Fri Nov 24 17:28:49 2023

root@attackdefense:~# enum4linux -i 192.134.130.3
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Nov 24 17:30:11 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.134.130.3
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

 ===================================================== 
|    Enumerating Workgroup/Domain on 192.134.130.3    |
 ===================================================== 
[+] Got domain/workgroup name: RECONLABS

 ====================================== 
|    Session Check on 192.134.130.3    |
 ====================================== 
[+] Server 192.134.130.3 allows sessions using username '', password ''

 ============================================ 
|    Getting domain SID for 192.134.130.3    |
 ============================================ 
Domain Name: RECONLABS
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ============================================== 
|    Getting printer info for 192.134.130.3    |
 ============================================== 
No printers returned.

enum4linux complete on Fri Nov 24 17:30:12 2023
```

rpcclient

```
root@attackdefense:~# rpcclient -U "" -N 192.134.130.3   
rpcclient $> enumdomgroups
group:[Maintainer] rid:[0x3ee]
group:[Reserved] rid:[0x3ef]
```

smbclient

```
root@attackdefense:~# smbclient -L 192.134.130.3 -N

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

root@attackdefense:~# smbclient //192.134.130.3/Public -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Nov 24 17:25:35 2023
  ..                                  D        0  Tue Nov 27 13:36:13 2018
  secret                              D        0  Tue Nov 27 13:36:13 2018
  dev                                 D        0  Tue Nov 27 13:36:13 2018

                1981084628 blocks of size 1024. 193109848 blocks available
smb: \> cd secret\
smb: \secret\> ls
  .                                   D        0  Tue Nov 27 13:36:13 2018
  ..                                  D        0  Fri Nov 24 17:25:35 2023
  flag                                N       33  Tue Nov 27 13:36:13 2018

                1981084628 blocks of size 1024. 193109956 blocks available
smb: \secret\> get flag
getting file \secret\flag of size 33 as flag (32.2 KiloBytes/sec) (average 32.2 KiloBytes/sec)
smb: \secret\> exit
root@attackdefense:~# cat flag
03ddb97933e716f5057a18632badb3b4
```
