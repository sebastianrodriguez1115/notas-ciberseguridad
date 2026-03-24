# nmap scripts

I have a question about this, why is this useful if I need the administrator password??

# smb-protocols

```
root@attackdefense:~# nmap -p445 --script smb-protocols 10.4.29.196
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-23 05:50 IST
Nmap scan report for 10.4.29.196
Host is up (0.0092s latency).

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

# smb-security-mode

```
root@attackdefense:~# nmap -p445 --script smb-security-mode 10.4.29.196
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-23 05:51 IST
Nmap scan report for 10.4.29.196
Host is up (0.0094s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)

Nmap done: 1 IP address (1 host up) scanned in 1.40 seconds
```

# smb-enum-sessions

```
root@attackdefense:~# nmap -p445 --script smb-enum-sessions --script-args smbusername=administrator,smbpassword=smbserver_771 10.4.29.196
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-23 05:57 IST
Nmap scan report for 10.4.29.196
Host is up (0.0091s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-sessions: 
|   Users logged in
|     WIN-OMCNBKR66MN\bob since 2023-11-23T00:19:15
|   Active SMB sessions
|_    ADMINISTRATOR is connected from \\10.10.23.5 for [just logged in, it's probably you], idle for [not idle]

Nmap done: 1 IP address (1 host up) scanned in 4.15 seconds
```

# smb-enum-shares

```
root@attackdefense:~# nmap -p445 --script smb-enum-shares 10.4.29.196
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-23 05:58 IST
Nmap scan report for 10.4.29.196
Host is up (0.0091s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.4.29.196\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.4.29.196\C: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|     Current user access: READ
...

root@attackdefense:~# nmap -p445 --script smb-enum-shares --script-args smbusername=administrator,smbpassword=smbserver_771 10.4.29.196
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-23 06:00 IST
Nmap scan report for 10.4.29.196
Host is up (0.0092s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-shares: 
|   account_used: administrator
|   \\10.4.29.196\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\Windows
|     Anonymous access: <none>
|     Current user access: READ/WRITE
...
```

# smb-enum-users

```
root@attackdefense:~# nmap -p445 --script smb-enum-users 10.4.29.196
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-23 06:01 IST
Nmap scan report for 10.4.29.196
Host is up (0.0088s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 4.70 seconds

root@attackdefense:~# nmap -p445 --script smb-enum-users --script-args smbusername=administrator,smbpassword=smbserver_771 10.4.29.196
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-23 06:01 IST
Nmap scan report for 10.4.29.196
Host is up (0.010s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-users: 
|   WIN-OMCNBKR66MN\Administrator (RID: 500)
|     Description: Built-in account for administering the computer/domain
|     Flags:       Password does not expire, Normal user account
|   WIN-OMCNBKR66MN\bob (RID: 1010)
|     Flags:       Password does not expire, Normal user account
|   WIN-OMCNBKR66MN\Guest (RID: 501)
|     Description: Built-in account for guest access to the computer/domain
|_    Flags:       Password does not expire, Password not required, Normal user account

Nmap done: 1 IP address (1 host up) scanned in 4.71 seconds
```

# smb-enum-domains

```
root@attackdefense:~# nmap -p445 --script smb-enum-domains --script-args smbusername=administrator,smbpassword=smbserver_771 10.4.29.196
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-23 06:03 IST
Nmap scan report for 10.4.29.196
Host is up (0.0096s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-domains: 
|   WIN-OMCNBKR66MN
|     Groups: WinRMRemoteWMIUsers__
|     Users: Administrator, bob, Guest
|     Creation time: 2013-08-22T14:47:57
|     Passwords: min length: n/a; min age: n/a days; max age: 42 days; history: n/a passwords
|     Properties: Complexity requirements exist
|     Account lockout disabled
|   Builtin
|     Groups: Access Control Assistance Operators, Administrators, Backup Operators, Certificate Service DCOM Access, Cryptographic Operators, Distributed COM Users, Event Log Readers, Guests, Hyper-V Administrators, IIS_IUSRS, Network Configuration Operators, Performance Log Users, Performance Monitor Users, Power Users, Print Operators, RDS Endpoint Servers, RDS Management Servers, RDS Remote Access Servers, Remote Desktop Users, Remote Management Users, Replicator, Users
|     Users: n/a
|     Creation time: 2013-08-22T14:47:57
|     Passwords: min length: n/a; min age: n/a days; max age: 42 days; history: n/a passwords
|_    Account lockout disabled

Nmap done: 1 IP address (1 host up) scanned in 4.07 seconds
```

# smb-enum-groups

```
root@attackdefense:~# nmap -p445 --script smb-enum-groups --script-args smbusername=administrator,smbpassword=smbserver_771 10.4.29.196
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-23 06:05 IST
Nmap scan report for 10.4.29.196
Host is up (0.0094s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-enum-groups: 
|   Builtin\Administrators (RID: 544): Administrator, bob
|   Builtin\Users (RID: 545): bob
|   Builtin\Guests (RID: 546): Guest
|   Builtin\Power Users (RID: 547): <empty>
|   Builtin\Print Operators (RID: 550): <empty>
|   Builtin\Backup Operators (RID: 551): <empty>
|   Builtin\Replicator (RID: 552): <empty>
|   Builtin\Remote Desktop Users (RID: 555): bob
|   Builtin\Network Configuration Operators (RID: 556): <empty>
|   Builtin\Performance Monitor Users (RID: 558): <empty>
|   Builtin\Performance Log Users (RID: 559): <empty>
|   Builtin\Distributed COM Users (RID: 562): <empty>
|   Builtin\IIS_IUSRS (RID: 568): <empty>
|   Builtin\Cryptographic Operators (RID: 569): <empty>
|   Builtin\Event Log Readers (RID: 573): <empty>
|   Builtin\Certificate Service DCOM Access (RID: 574): <empty>
|   Builtin\RDS Remote Access Servers (RID: 575): <empty>
|   Builtin\RDS Endpoint Servers (RID: 576): <empty>
|   Builtin\RDS Management Servers (RID: 577): <empty>
|   Builtin\Hyper-V Administrators (RID: 578): <empty>
|   Builtin\Access Control Assistance Operators (RID: 579): <empty>
|   Builtin\Remote Management Users (RID: 580): <empty>
|_  WIN-OMCNBKR66MN\WinRMRemoteWMIUsers__ (RID: 1000): <empty>

Nmap done: 1 IP address (1 host up) scanned in 4.48 seconds
```

# smb-enum-services

```
root@attackdefense:~# nmap -p445 --script smb-enum-services --script-args smbusername=administrator,smbpassword=smbserver_771 10.4.29.196
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-23 06:05 IST
Nmap scan report for 10.4.29.196
Host is up (0.0091s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds
| smb-enum-services: 
|   AmazonSSMAgent: 
|     display_name: Amazon SSM Agent
|     state: 
|       SERVICE_PAUSE_PENDING
|       SERVICE_RUNNING
|       SERVICE_CONTINUE_PENDING
|       SERVICE_PAUSED
|     type: 
|       SERVICE_TYPE_WIN32
|       SERVICE_TYPE_WIN32_OWN_PROCESS
|     controls_accepted: 
|       SERVICE_CONTROL_INTERROGATE
|       SERVICE_CONTROL_NETBINDADD
|       SERVICE_CONTROL_NETBINDENABLE
|       SERVICE_CONTROL_CONTINUE
|       SERVICE_CONTROL_PARAMCHANGE
|       SERVICE_CONTROL_STOP
...
```
