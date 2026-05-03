---
title: Enumeración DNS (Domain Name System)
slug: enumeracion-dns
aliases: [Enumeración DNS (Domain Name System)]
fase: [Enumeración]
plataforma: Multi
dificultad: Básica
mitre: [T1590.002]
related: []
learning_refs: []
---

# Enumeración DNS (Domain Name System)

## Descripción
El DNS traduce nombres de dominio a direcciones IP y almacena registros de infraestructura (A, AAAA, MX, NS, TXT, CNAME, PTR). La enumeración DNS permite descubrir subdominios, servidores de correo, nameservers, transferencias de zona y la infraestructura interna de un objetivo. Una transferencia de zona DNS mal configurada (AXFR sin autenticación) puede revelar la topología completa de la red interna. Combina técnicas pasivas (sin interacción directa) y activas (consultas directas al DNS).

## Herramientas
- **dnsrecon** — reconocimiento DNS automatizado (lookups, transferencia de zona, brute force, cache snooping)
- **nslookup** — consulta DNS básica interactiva y en batch
- **dig** — consultas DNS avanzadas con salida detallada
- **gobuster** (modo dns) — fuerza bruta de subdominios
- **amass** — enumeración exhaustiva de subdominios con múltiples fuentes y modo `-active`
- **subfinder** — enumeración rápida de subdominios vía APIs pasivas
- **ldns-walk** — herramienta especializada en NSEC walking (zonas DNSSEC mal configuradas)
- **dnsdumpster.com** — enumeración pasiva vía servicio web

## Comandos / Ejemplos

### Consultas DNS básicas
```bash
# nslookup - resolución directa
nslookup facebook.com
nslookup -type=MX target.com    # registros de correo
nslookup -type=NS target.com    # nameservers

# dig - consultas avanzadas
dig target.com
dig target.com MX               # registros MX
dig target.com NS               # nameservers
dig +short target.com           # solo la IP
dig @ns1.target.com target.com  # consulta a nameserver específico
```

### Transferencia de zona (AXFR)
```bash
# Si el servidor permite AXFR → revela todos los registros DNS del dominio
dig @ns1.target.com target.com AXFR

# Con dnsrecon
dnsrecon -d target.com -t axfr

# Con host
host -l target.com ns1.target.com
```

### dnsrecon - reconocimiento completo
```bash
# Lookup inverso en rango de IPs
dnsrecon -r 127.0.0.0/24 -n 192.168.138.130 -d blah
# -r: rango IP, -n: servidor DNS, -d: dominio

# Enumeración estándar del dominio
dnsrecon -d target.com

# Brute force de subdominios
dnsrecon -d target.com -D /usr/share/wordlists/dnsmap.txt -t brt
```

### Fuerza bruta de subdominios
```bash
# gobuster - DNS bruteforce
gobuster dns -d target.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# amass - enumeración exhaustiva (múltiples fuentes + brute force)
amass enum -d tesla.com -v
amass enum -d target.com -brute -w wordlist.txt

# subfinder - enumeración rápida vía APIs pasivas
subfinder -d tesla.com
# Pipeline con httpx para verificar activos vivos:
cat subfinder.txt | httpx | sort -u > activos_vivos.txt
```

### Técnicas avanzadas

#### NSEC Walking (zonas DNSSEC mal configuradas)
```bash
ldns-walk @ns1.target.com target.com
```
Si DNSSEC está activo pero usa registros NSEC en lugar de NSEC3, los registros encadenan los nombres existentes en orden alfabético, permitiendo "caminar" la zona y descubrir todos los registros existentes. NSEC3 mitiga esto usando hashes.

#### DNS Cache Snooping
```bash
dnsrecon -t snoop -n 8.8.8.8 -D subdomains.txt
```
Verifica si el servidor DNS objetivo (aquí `8.8.8.8`) tiene en caché los dominios de la lista. Un hit indica que el dominio ha sido resuelto recientemente por usuarios de ese servidor DNS, revelando información sobre qué dominios visitan los usuarios de la organización. Útil contra DNS resolvers internos accesibles externamente.

#### Amass en modo activo
```bash
amass enum -active -d target.com -ip -src
```
La opción `-active` añade a la enumeración pasiva: brute force de subdominios, extracción de SAN de certificados TLS de los servicios encontrados, intentos de transferencia de zona. Es la enumeración DNS más completa disponible en una sola herramienta.

### Herramientas online (pasivas)
- `https://dnsdumpster.com/` — mapa DNS del dominio sin interacción directa
- `https://securitytrails.com/` — historial DNS y subdominios
- `https://crt.sh/?q=%.target.com` — subdominios vía certificados TLS

**Registros DNS relevantes:**
| Tipo | Descripción |
|------|-------------|
| A    | IPv4 del dominio |
| AAAA | IPv6 del dominio |
| MX   | Servidores de correo |
| NS   | Nameservers autoritativos |
| TXT  | Verificación de dominio, SPF, DKIM |
| CNAME | Alias de dominio |
| PTR  | Lookup inverso (IP → nombre) |
| SOA  | Información de la zona DNS |

## Contramedidas
- Configurar el servidor DNS para denegar transferencias de zona (AXFR) a IPs no autorizadas
- Usar TSIG (Transaction Signature) para autenticar transferencias de zona entre nameservers
- Separar DNS interno (intranet) de DNS externo (no exponer registros internos)
- Monitorear consultas DNS anormales (alto volumen de NXDOMAIN puede indicar brute force)
- Implementar RPZ (Response Policy Zones) para bloquear dominios maliciosos
- **NSEC3 en lugar de NSEC** para zonas DNSSEC, mitigando el walking mediante hashes de los nombres
- **Limitar recursión** en el servidor DNS para no permitir consultas recursivas desde el exterior (mitiga Cache Snooping)
- **Rate limiting** por IP origen para mitigar fuerza bruta de subdominios

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1590.002: Gather Victim Network Information: DNS. https://attack.mitre.org/techniques/T1590/002/
