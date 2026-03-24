# HTTP IIS Nmap Script

nmap http-enum

```
root@attackdefense:~# nmap -sV -p 80 --script http-enum 10.4.31.227
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-26 03:15 IST
Nmap scan report for 10.4.31.227
Host is up (0.0093s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-enum: 
|   /content/: Potentially interesting folder
|   /downloads/: Potentially interesting folder
|_  /webdav/: Potentially interesting folder
|_http-server-header: Microsoft-IIS/10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.94 seconds
```

nmap http-headers

```
root@attackdefense:~# nmap -sV -p 80 --script http-headers 10.4.31.227
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-26 03:16 IST
Nmap scan report for 10.4.31.227
Host is up (0.0091s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
| http-headers: 
|   Cache-Control: private
|   Content-Type: text/html; charset=utf-8
|   Location: /Default.aspx
|   Server: Microsoft-IIS/10.0
|   Set-Cookie: ASP.NET_SessionId=f1wck0yi0mqawrbstd4xpmqu; path=/; HttpOnly; SameSite=Lax
|   X-AspNet-Version: 4.0.30319
|   Set-Cookie: Server=RE9UTkVUR09BVA==; path=/
|   X-XSS-Protection: 0
|   X-Powered-By: ASP.NET
|   Date: Sat, 25 Nov 2023 21:46:39 GMT
|   Connection: close
|   Content-Length: 130
|   
|_  (Request type: GET)
|_http-server-header: Microsoft-IIS/10.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.97 seconds
```

nmap http-webdav-scan

```
root@attackdefense:~# nmap -sV -p 80 --script http-webdav-scan --script-args http-methods.url-path=/webdav/ 10.4.31.227
Starting Nmap 7.91 ( https://nmap.org ) at 2023-11-26 03:20 IST
Nmap scan report for 10.4.31.227
Host is up (0.010s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-webdav-scan: 
|   Allowed Methods: OPTIONS, TRACE, GET, HEAD, POST, COPY, PROPFIND, LOCK, UNLOCK
|   Server Type: Microsoft-IIS/10.0
|   WebDAV type: Unknown
|   Server Date: Sat, 25 Nov 2023 21:50:32 GMT
|_  Public Options: OPTIONS, TRACE, GET, HEAD, POST, PROPFIND, PROPPATCH, MKCOL, PUT, DELETE, COPY, MOVE, LOCK, UNLOCK
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.81 seconds
```
