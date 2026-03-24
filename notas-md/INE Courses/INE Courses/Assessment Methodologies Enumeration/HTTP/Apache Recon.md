# Apache Recon

msfconsole

```
msf6 > use auxiliary/scanner/http/brute_dirs 
msf6 auxiliary(scanner/http/brute_dirs) > set rhosts 192.3.62.3
rhosts => 192.3.62.3
msf6 auxiliary(scanner/http/brute_dirs) > exploit

[*] Using code '404' as not found.
[+] Found http://192.3.62.3:80/dir/ 200
[+] Found http://192.3.62.3:80/src/ 200
[*] Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```
