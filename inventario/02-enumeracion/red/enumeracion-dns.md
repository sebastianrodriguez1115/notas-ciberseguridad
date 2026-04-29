# Enumeración DNS (Domain Name System)

## Descripción
El DNS traduce nombres de dominio a direcciones IP y almacena registros de infraestructura (A, AAAA, MX, NS, TXT, CNAME, PTR). La enumeración DNS permite descubrir subdominios, servidores de correo, nameservers, transferencias de zona y la infraestructura interna de un objetivo. Una transferencia de zona DNS mal configurada (AXFR sin autenticación) puede revelar la topología completa de la red interna. Combina técnicas pasivas (sin interacción directa) y activas (consultas directas al DNS).

## Clasificación
- **Fase**: Enumeración
- **MITRE ATT&CK**: T1590.002 (Gather Victim Network Information: DNS)
- **Plataforma**: Multi
- **Dificultad**: Básica

## Herramientas
- **dnsrecon** — reconocimiento DNS automatizado (lookups, transferencia de zona, brute force)
- **nslookup** — consulta DNS básica interactiva y en batch
- **dig** — consultas DNS avanzadas con salida detallada
- **gobuster** (modo dns) — fuerza bruta de subdominios
- **amass** — enumeración exhaustiva de subdominios con múltiples fuentes
- **subfinder** — enumeración rapida de subdominios vía APIs pasivas
- **dnsdumpster.com** — enumeración pasiva vía servicio web

## Comandos / Ejemplos

### Consultas DNS basicas
```bash
# nslookup - resolucion directa
nslookup facebook.com
nslookup -type=MX target.com    # registros de correo
nslookup -type=NS target.com    # nameservers

# dig - consultas avanzadas
dig target.com
dig target.com MX               # registros MX
dig target.com NS               # nameservers
dig +short target.com           # solo la IP
dig @ns1.target.com target.com  # consulta a nameserver especifico
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

# Enumeracion estandar del dominio
dnsrecon -d target.com

# Brute force de subdominios
dnsrecon -d target.com -D /usr/share/wordlists/dnsmap.txt -t brt
```

### Fuerza bruta de subdominios
```bash
# gobuster - DNS bruteforce
gobuster dns -d target.com -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# amass - enumeracion exhaustiva (multiples fuentes + brute force)
amass enum -d tesla.com -v
amass enum -d target.com -brute -w wordlist.txt

# subfinder - enumeracion rapida via APIs pasivas
subfinder -d tesla.com
# Pipeline con httpx para verificar activos vivos:
cat subfinder.txt | httpx | sort -u > activos_vivos.txt
```

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

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1590.002: Gather Victim Network Information: DNS. https://attack.mitre.org/techniques/T1590/002/
