# Brute Force

<a href="Brute%20Force/Hydra%20819e636257574d8f82b53f1087539708.html">Hydra</a>

# PDF Passwords

```
pdfcrack -f flag.pdf -w /usr/share/wordlists/rockyou.txt 
```

# ZIP Passwords

```
ubuntu@tryhackme:~/Desktop$ zip2john flag.zip > ziphash.txt 
ubuntu@tryhackme:~/Desktop$ john --wordlist=/usr/share/wordlists/rockyou.txt ziphash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Cost 1 (HMAC size [KiB]) is 1 for all loaded hashes
Will run 2 OpenMP threads
Press 'q' or Ctrl-C to abort, 'h' for help, almost any other key for status
winter4ever      (flag.zip/flag.txt)     
1g 0:00:00:00 DONE (2025-12-12 01:16) 1.754g/s 7185p/s 7185c/s 7185C/s friend..sahara
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
