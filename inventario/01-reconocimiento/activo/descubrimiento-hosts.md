# Descubrimiento de Hosts

## Descripcion
Tecnica que consiste en identificar hosts activos dentro de una red mediante sondeo activo. Se utilizan diversos protocolos como ICMP (ping), ARP (a nivel de capa 2) y TCP (SYN/ACK probes). Segun *Gray Hat Hacking*, en entornos modernos el descubrimiento de hosts es la fase donde mas se debe cuidar la evasion, ya que los firewalls suelen bloquear el trafico ICMP Echo Request estandar.

## Clasificacion
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: T1018 (Remote System Discovery) / T1595.001 (Active Scanning: Scanning IP Blocks)
- **Plataforma**: Multi
- **Dificultad**: Basica

## Herramientas
- **nmap** — Soporta metodos avanzados como ICMP Timestamp y Address Mask
- **arp-scan** — Indispensable para saltar firewalls de host en la misma red local
- **netdiscover** — Util para descubrimiento silencioso basado en trafico ARP existente
- **fping** — Optimo para scripting y descubrimiento masivo veloz

## Comandos / Ejemplos

### Descubrimiento ICMP Avanzado (Evasion)
```bash
nmap -sn -PE 192.168.1.0/24  # ICMP Echo (estandar)
nmap -sn -PP 192.168.1.0/24  # ICMP Timestamp (suele estar permitido si Echo esta bloqueado)
nmap -sn -PM 192.168.1.0/24  # ICMP Address Mask
```

### TCP SYN/ACK Ping (Capa 4)
```bash
nmap -sn -PS22,80,443 192.168.1.0/24  # TCP SYN Ping a puertos comunes
nmap -sn -PA80,443 192.168.1.0/24     # TCP ACK Ping (util para firewalls stateless)
```

### Evasion via Fragmentacion (Gray Hat Hacking)
```bash
nmap -sn --mtu 16 192.168.1.0/24
```
Fragmenta los paquetes en bloques de 16 bytes para evadir sistemas de deteccion que no realizan reensamblado de paquetes en el perimetro. Nota: `--mtu` requiere un valor multiplo de 8; usar `-f` sin `--mtu` fragmenta en bloques de 8 bytes.

### Descubrimiento ARP (Red Local)
```bash
nmap -sn -PR 192.168.1.0/24
arp-scan -l
```
El escaneo ARP es el mas fiable en redes locales ya que no puede ser filtrado por firewalls de host sin romper la conectividad de red basica.

## Contramedidas
- **Deshabilitar respuestas ICMP innecesarias**: Bloquear tipos de ICMP como Timestamp y Address Mask.
- **Implementar Firewall de Proxima Generacion (NGFW)**: Capaces de detectar escaneos fragmentados y anomalias ARP.
- **Port Security / Dynamic ARP Inspection (DAI)**: En switches, para prevenir el reconocimiento y spoofing ARP.
- **Segmentacion Zero Trust**: No confiar en el descubrimiento ARP limitando la visibilidad entre hosts de la misma VLAN.

## Referencias
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- Kim, P. (2018). *The Hacker Playbook 3: Practical Guide to Penetration Testing*. Secure Planet.
- Harper, A., Harris, S., Ness, J., Eagle, C., Lenkey, G., & Williams, T. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
- Notas del proyecto: notas-md/HNotes/Recon/Active Enumeration/nmap.md
- MITRE Corporation. (2024). ATT&CK Technique T1018: Remote System Discovery. https://attack.mitre.org/techniques/T1018/
