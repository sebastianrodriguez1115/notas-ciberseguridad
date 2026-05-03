---
title: Fuzzing de Directorios y Archivos Web
slug: fuzzing-directorios-archivos
aliases: [Fuzzing de Directorios y Archivos Web]
fase: [Enumeración]
plataforma: Web
dificultad: Básica
mitre: [T1595.002]
related: []
learning_refs: []
---

# Fuzzing de Directorios y Archivos Web

## Descripción
Técnica de descubrimiento de directorios, archivos y rutas ocultas en servidores web mediante el envío sistemático de peticiones HTTP usando una wordlist. Permite encontrar recursos no enlazados públicamente: paneles de administración, archivos de configuración, backups, scripts expuestos y cualquier ruta accesible que no este referenciada en el sitio. Es una de las técnicas mas productivas en la fase de enumeración web.

## Herramientas
- **ffuf** — fuzzer web rápido y flexible; el marcador `FUZZ` puede ir en cualquier posición de la URL
- **gobuster** — fuerza bruta de directorios/archivos con soporte de extensiones múltiples

## Comandos / Ejemplos

### ffuf - directorios
```bash
# Enumeracion basica de directorios
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
  -u http://SERVER_IP:PORT/FUZZ

# Wordlist raft-large (mas exhaustivo, recomendado para CTFs y pentests)
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/raft-large-directories.txt:FUZZ \
  -u http://TARGET/FUZZ

# Fuzzing recursivo con extension .php (profundidad 1)
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ \
  -u http://SERVER_IP:PORT/FUZZ \
  -recursion -recursion-depth 1 \
  -e .php -v

# Fuzzing de extensiones en un path conocido
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ \
  -u http://SERVER_IP:PORT/blog/indexFUZZ
```

### ffuf - archivos especificos
```bash
# Descubrimiento de archivos con raft-large-files
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/raft-large-files.txt:FUZZ \
  -H "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0" \
  -u http://TARGET/FUZZ

# Filtrar por codigo de respuesta (solo 200)
ffuf -w wordlist.txt:FUZZ -u http://TARGET/FUZZ -mc 200

# Filtrar por tamano de respuesta (excluir respuesta de error 404)
ffuf -w wordlist.txt:FUZZ -u http://TARGET/FUZZ -fs 1234
```

### gobuster - directorios y archivos
```bash
# Enumeracion basica
gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt

# Con multiples extensiones (archivos backup, temp, codigo fuente)
gobuster dir -u http://MACHINE_IP/who/ -w wordlist.txt \
  -x php,php~,bak,orig,save,swp,swo,txt,zip
# El flag -x agrega cada extension a cada entrada de la wordlist

# Con autenticacion HTTP Basic
gobuster dir -u http://TARGET -w wordlist.txt -U admin -P password
```

**Status codes relevantes:**
| Código | Significado |
|--------|-------------|
| 200 | OK — recurso existe y es accesible |
| 301/302 | Redirect — puede llevar a contenido interesante |
| 403 | Forbidden — existe pero sin permisos (intentar bypass) |
| 401 | Unauthorized — requiere autenticación |
| 404 | Not Found — no existe |

**Wordlists recomendadas:**
| Wordlist | Uso |
|----------|-----|
| `raft-large-directories.txt` | Directorios (exhaustivo) |
| `raft-large-files.txt` | Archivos especificos |
| `directory-list-2.3-medium.txt` | Equilibrio velocidad/cobertura |
| `common.txt` (dirb) | Rápido, para primeras exploraciones |

## Contramedidas
- Implementar un WAF con reglas para detectar patrones de directory brute-forcing
- Configurar rate limiting para bloquear IPs con alto volumen de peticiones 404
- Remover archivos de debug, backup y configuración del entorno de producción
- Deshabilitar el listado de directorios (directory listing) en el servidor web
- Usar paths no predecibles para recursos sensibles en lugar de nombres comunes

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- OccupyTheWeb. (2018). *Linux Basics for Hackers*. No Starch Press.
- MITRE Corporation. (2024). ATT&CK Technique T1595.002: Active Scanning: Vulnerability Scanning. https://attack.mitre.org/techniques/T1595/002/
- danielmiessler. (s.f.). *SecLists* [Repositorio]. GitHub. https://github.com/danielmiessler/SecLists
