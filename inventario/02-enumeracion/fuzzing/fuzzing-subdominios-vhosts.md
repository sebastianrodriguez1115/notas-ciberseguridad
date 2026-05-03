---
title: Fuzzing de Subdominios y Virtual Hosts
slug: fuzzing-subdominios-vhosts
aliases: [Fuzzing de Subdominios y Virtual Hosts]
fase: [Enumeración]
plataforma: Web
dificultad: Básica
mitre: [T1595.002]
related: []
learning_refs: []
---

# Fuzzing de Subdominios y Virtual Hosts

## Descripción
Técnica de descubrimiento de subdominios y Virtual Hosts (VHosts) de un objetivo mediante fuerza bruta. Existen dos modalidades distintas: (1) DNS fuzzing, que prueba si un nombre resuelve en el DNS; y (2) VHost fuzzing, que manipula el header HTTP `Host` para descubrir aplicaciones web que comparten la misma IP pero responden a nombres de host diferentes. El VHost fuzzing es especialmente util cuando el servidor web aloja múltiples aplicaciones en la misma IP y el DNS interno no es accesible desde el atacante.

## Herramientas
- **ffuf** — fuzzing de subdominios vía URL o vía header Host
- **gobuster** (modo dns) — brute force de subdominios DNS
- **amass** — enumeración exhaustiva con múltiples fuentes (pasivas + activas)
- **subfinder** — enumeración rapida vía APIs pasivas (Shodan, VirusTotal, etc.)
- **httpx** — verificar cuales de los subdominios encontrados estan activos

## Comandos / Ejemplos

### DNS fuzzing con ffuf (resolución DNS directa)
```bash
# El subdominio se prueba como parte del hostname en la URL
# Requiere que el wildcard DNS este desactivado en el objetivo
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://FUZZ.academy.htb:59903/

# Lista mas exhaustiva (110k entradas)
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ \
  -u http://FUZZ.TARGET.com/
```

### VHost fuzzing con ffuf (header Host)
```bash
# Prueba nombres en el header Host manteniendo la misma IP
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
  -u http://academy.htb:59903/ \
  -H 'Host: FUZZ.academy.htb'

# Con filtro de tamano (eliminar respuestas identicas que no son un VHost real)
ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt:FUZZ \
  -H "Host: FUZZ.lookup.thm" \
  -fs 0 \
  -u http://lookup.thm/
# -fs 0: filtra respuestas de tamano 0 (subdominio inexistente)
# Ajustar -fs con el tamano de la respuesta de error base
```

### gobuster - DNS bruteforce
```bash
gobuster dns -d target.com \
  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Con mayor verbosidad
gobuster dns -d target.com -w wordlist.txt -v
```

### amass y subfinder - enumeración combinada
```bash
# amass - exhaustivo (brute force + fuentes pasivas + certificados)
amass enum -d tesla.com -v
amass enum -d target.com -brute -w wordlist.txt

# subfinder - rapido (solo fuentes pasivas/APIs)
subfinder -d tesla.com

# Pipeline: subfinder + httpx para verificar activos vivos
subfinder -d target.com -o subdominios.txt
cat subdominios.txt | httpx | sort -u > activos_vivos.txt
```

**DNS fuzzing vs VHost fuzzing:**
| Aspecto | DNS Fuzzing | VHost Fuzzing |
|---------|-------------|---------------|
| Mecanismo | Resolución DNS real | Header HTTP `Host` |
| Requisito | DNS accesible | Solo acceso HTTP a la IP |
| Cuando usar | Subdominios publicos | Apps internas en misma IP |
| Detecta | `app.target.com` | Servidor respondiendo a `app.target.com` aunque no resuelva |

**Filtrado de falsos positivos:**
- Usar `-fs` (filter size) para excluir respuestas del mismo tamaño que la respuesta de error
- Usar `-fc` (filter status code) para excluir codigos no deseados
- Comparar el tamaño de respuesta base (sin FUZZ valido) antes de lanzar el ataque

## Contramedidas
- Implementar wildcard DNS que resuelva todos los subdominios a una página generica (dificulta DNS fuzzing)
- Monitorear anomalias en el trafico DNS (alto volumen de consultas NXDOMAIN)
- Usar un WAF para detectar y bloquear patrones de VHost fuzzing
- Implementar rate limiting por IP en el servidor HTTP
- Mantener privados los subdominios de entornos de desarrollo/staging usando DNS split-horizon

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1595.002: Active Scanning: Vulnerability Scanning. https://attack.mitre.org/techniques/T1595/002/
- danielmiessler. (s.f.). *SecLists* [Repositorio]. GitHub. https://github.com/danielmiessler/SecLists
