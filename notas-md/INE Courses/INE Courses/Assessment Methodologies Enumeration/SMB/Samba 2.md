# Samba 2

# nmap enum

```
root@attackdefense:~# nmap 192.104.204.3
Starting Nmap 7.70 ( https://nmap.org ) at 2023-11-24 15:26 UTC
Nmap scan report for target-1 (192.104.204.3)
Host is up (0.000012s latency).
Not shown: 998 closed ports
PORT    STATE SERVICE
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:68:CC:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.21 seconds
root@attackdefense:~# nmap 192.104.204.3 -p445 -sV
Starting Nmap 7.70 ( https://nmap.org ) at 2023-11-24 15:27 UTC
Nmap scan report for target-1 (192.104.204.3)
Host is up (0.000050s latency).

PORT    STATE SERVICE     VERSION
445/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: RECONLABS)
MAC Address: 02:42:C0:68:CC:03 (Unknown)
Service Info: Host: SAMBA-RECON

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.61 seconds

root@attackdefense:~# nmap 192.104.204.3 -p445 --script smb-protocols
Starting Nmap 7.70 ( https://nmap.org ) at 2023-11-24 15:30 UTC
Nmap scan report for target-1 (192.104.204.3)
Host is up (0.000076s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:68:CC:03 (Unknown)

Host script results:
| smb-protocols: 
|   dialects: 
|     NT LM 0.12 (SMBv1) [dangerous, but default]
|     2.02
|     2.10
|     3.00
|     3.02
|_    3.11

root@attackdefense:~# nmap 192.104.204.3 -p445 --script smb-enum-users
Starting Nmap 7.70 ( https://nmap.org ) at 2023-11-24 15:32 UTC
Nmap scan report for target-1 (192.104.204.3)
Host is up (0.000042s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
MAC Address: 02:42:C0:68:CC:03 (Unknown)

Host script results:
| smb-enum-users: 
|   SAMBA-RECON\admin (RID: 1005)
|     Full name:   
|     Description: 
|     Flags:       Normal user account
|   SAMBA-RECON\aisha (RID: 1004)
|     Full name:   
|     Description: 
|     Flags:       Normal user account
|   SAMBA-RECON\elie (RID: 1002)
|     Full name:   
|     Description: 
|     Flags:       Normal user account
|   SAMBA-RECON\emma (RID: 1003)
|     Full name:   
|     Description: 
|     Flags:       Normal user account
|   SAMBA-RECON\john (RID: 1000)
|     Full name:   
|     Description: 
|     Flags:       Normal user account
|   SAMBA-RECON\shawn (RID: 1001)
|     Full name:   
|     Description: 
|_    Flags:       Normal user account
```

# rpcclient info

```
root@attackdefense:~# rpcclient -U "" -N 192.104.204.3
rpcclient $> srvinfo
        SAMBA-RECON    Wk Sv PrQ Unx NT SNT samba.recon.lab
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03
rpcclient $> enumdomusers
user:[john] rid:[0x3e8]
user:[elie] rid:[0x3ea]
user:[aisha] rid:[0x3ec]
user:[shawn] rid:[0x3e9]
user:[emma] rid:[0x3eb]
user:[admin] rid:[0x3ed]
rpcclient $> lookupnames admin
admin S-1-5-21-4056189605-2085045094-1961111545-1005 (User: 1)
```

# enum4linux

```
root@attackdefense:~# enum4linux -o 192.104.204.3
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Nov 24 15:28:25 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.104.204.3
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

 ===================================================== 
|    Enumerating Workgroup/Domain on 192.104.204.3    |
 ===================================================== 
[+] Got domain/workgroup name: RECONLABS

 ====================================== 
|    Session Check on 192.104.204.3    |
 ====================================== 
[+] Server 192.104.204.3 allows sessions using username '', password ''

 ============================================ 
|    Getting domain SID for 192.104.204.3    |
 ============================================ 
Domain Name: RECONLABS
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ======================================= 
|    OS information on 192.104.204.3    |
 ======================================= 
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.
[+] Got OS info for 192.104.204.3 from smbclient: 
[+] Got OS info for 192.104.204.3 from srvinfo:
        SAMBA-RECON    Wk Sv PrQ Unx NT SNT samba.recon.lab
        platform_id     :       500
        os version      :       6.1
        server type     :       0x809a03
enum4linux complete on Fri Nov 24 15:28:26 2023

root@attackdefense:~# enum4linux -U 192.104.204.3 
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Nov 24 15:33:32 2023

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 192.104.204.3
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

 ===================================================== 
|    Enumerating Workgroup/Domain on 192.104.204.3    |
 ===================================================== 
[+] Got domain/workgroup name: RECONLABS

 ====================================== 
|    Session Check on 192.104.204.3    |
 ====================================== 
[+] Server 192.104.204.3 allows sessions using username '', password ''

 ============================================ 
|    Getting domain SID for 192.104.204.3    |
 ============================================ 
Domain Name: RECONLABS
Domain Sid: (NULL SID)
[+] Can't determine if host is part of domain or part of a workgroup

 ============================== 
|    Users on 192.104.204.3    |
 ============================== 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: john     Name:   Desc: 
index: 0x2 RID: 0x3ea acb: 0x00000010 Account: elie     Name:   Desc: 
index: 0x3 RID: 0x3ec acb: 0x00000010 Account: aisha    Name:   Desc: 
index: 0x4 RID: 0x3e9 acb: 0x00000010 Account: shawn    Name:   Desc: 
index: 0x5 RID: 0x3eb acb: 0x00000010 Account: emma     Name:   Desc: 
index: 0x6 RID: 0x3ed acb: 0x00000010 Account: admin    Name:   Desc: 

user:[john] rid:[0x3e8]
user:[elie] rid:[0x3ea]
user:[aisha] rid:[0x3ec]
user:[shawn] rid:[0x3e9]
user:[emma] rid:[0x3eb]
user:[admin] rid:[0x3ed]
enum4linux complete on Fri Nov 24 15:33:33 2023
```

# Metasploit

```
msf5 > use auxiliary/scanner/smb/smb2 
msf5 auxiliary(scanner/smb/smb2) > set RHOSTS 192.104.204.3
RHOSTS => 192.104.204.3
msf5 auxiliary(scanner/smb/smb2) > run

[+] 192.104.204.3:445     - 192.104.204.3 supports SMB 2 [dialect 255.2] and has been online for 3707031 hours
[*] 192.104.204.3:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
