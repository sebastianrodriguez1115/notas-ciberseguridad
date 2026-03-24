# ****Assessment Methodologies: Footprinting & Scanning****

<a href="Assessment%20Methodologies%20Footprinting%20&amp;%20Scanning/Windows%20Recon%20Zenmap%20LAB%20c24ec9c27a154eb2a96a72243e69ccb1.html">Windows Recon: Zenmap LAB</a>

# Mapping a network:

To map a network using Nmap, you can use the following command:

```
nmap -sn <target IP range>
```

This command will perform a ping scan (-sn) on the specified target IP range. Nmap will send ICMP echo requests to the IP addresses in the range and determine which hosts are online.

Zenmap is the graphical user interface (GUI) for the Nmap network scanning tool. It provides an intuitive way to interact with Nmap and visualize the results of network scans. With Zenmap, users can easily configure and execute scans, view scan results, and analyze network information.

# Port Scanning

To perform port scanning with Nmap, you can use the following command:

```
nmap -p <port range> <target IP>
```

Replace `<port range>` with the desired range of ports to scan (e.g., 1-100) and `<target IP>` with the IP address of the target system. This command will scan the specified ports on the target system and provide information about which ports are open and potentially vulnerable.
