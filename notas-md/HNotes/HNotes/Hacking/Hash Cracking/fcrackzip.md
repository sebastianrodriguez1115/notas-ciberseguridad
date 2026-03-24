# fcrackzip

**fcrackzip** is a command-line tool used for cracking password-protected zip files. It is commonly used to recover lost or forgotten passwords for zip archives. The provided command installs fcrackzip using apt package manager and then demonstrates how to use it to crack a zip file named "file.zip" using the rockyou.txt wordlist.

```
apt install fcrackzip
fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt file.zip
```
