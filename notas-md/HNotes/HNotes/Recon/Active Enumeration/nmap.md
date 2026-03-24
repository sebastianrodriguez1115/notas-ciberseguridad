⭐

# nmap

Nmap (Network Mapper) is a powerful and versatile open-source tool used for network discovery and security auditing. It is designed to rapidly scan large networks, although it can also be used to scan single hosts. Nmap uses raw IP packets in novel ways to determine:

- What hosts are available on the network

<!-- -->

- What services (application name and version) those hosts are offering

<!-- -->

- What operating systems (and OS versions) they are running

<!-- -->

- What type of packet filters/firewalls are in use

<!-- -->

- And dozens of other characteristics

The command shown below is an example of how to use nmap:

```
nmap -T4 -p- -A 192.168.20.33
```

-Pn don’t perform ping

-sV service version scan

-O OS scan

-oX \[Filename\] output to XML

-sn ping scan
