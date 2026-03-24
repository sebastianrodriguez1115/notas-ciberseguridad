# CHANGELOG - Inventario de Técnicas de Ciberseguridad

Todos los cambios notables en este proyecto serán documentados en este archivo.

## [2026-03-23] — Sesion 2

### Añadido
- **Fase 02 - Enumeracion Web** (5 tecnicas): `fingerprinting-tecnologias-web.md`, `enumeracion-http-nmap.md`, `enumeracion-webdav.md`, `nikto.md`, `banner-grabbing-http.md`.
- **Fase 02 - Enumeracion Red** (4 tecnicas): `enumeracion-smb.md`, `enumeracion-snmp.md`, `enumeracion-nfs.md`, `enumeracion-dns.md`.
- **Fase 02 - Enumeracion Servicios** (6 tecnicas): `enumeracion-ssh.md`, `enumeracion-ftp.md`, `enumeracion-mysql.md`, `enumeracion-mssql.md`, `enumeracion-rdp.md`, `enumeracion-winrm.md`.
- **Fase 02 - Fuzzing** (4 tecnicas): `fuzzing-directorios-archivos.md`, `fuzzing-subdominios-vhosts.md`, `fuzzing-parametros.md`, `fuzzing-lfi-ssrf.md`.

### Corregido (Fase 02 — post-review)
- **MITRE IDs fuzzing**: `fuzzing-directorios-archivos.md` y `fuzzing-lfi-ssrf.md` T1083→T1595.002 (T1083 es post-compromiso local, no fuzzing HTTP externo).
- **MITRE IDs fuzzing**: `fuzzing-subdominios-vhosts.md` T1595.001→T1595.002 (T1595.001 modela IP block scanning, no subdomain enum).
- **MITRE IDs enumeracion**: `enumeracion-webdav.md` añadido T1190; `enumeracion-nfs.md` añadido T1548.001; `enumeracion-smb.md` expandido a T1087+T1069+T1007+T1110.
- **MITRE IDs servicios**: `enumeracion-ssh.md` y `enumeracion-ftp.md` corregidos — ID principal ahora T1046 (enumeracion), T1110.001 como secundario (fuerza bruta).
- **Herramienta deprecada**: `enumeracion-winrm.md` — reemplazado CrackMapExec (archivado 2024) por NetExec (`nxc`).
- **Referencias invalidas**: Reemplazado `Engebretson (2013)` en `nikto.md` y `enumeracion-ftp.md` (libro no disponible en `referencias/`) por `Gray Hat Hacking`.
- **Autoria incorrecta**: Corregido `Metasploit for Beginners` en `enumeracion-mysql.md` y `enumeracion-mssql.md` → autor correcto: Rahalkar, S. (2017).

---

## [2026-03-23] — Sesion 1

### Añadido
- **Fuentes de Internet**: Agregadas 30+ fuentes organizadas en 7 categorías al `AGENTS.md` (MITRE ATT&CK, OWASP, NVD, Exploit-DB, HackTricks, GTFOBins, LOLBAS, PTES, OSSTMM, NIST, etc.).
- **Fase 01 - Reconocimiento Pasivo** (8 técnicas): `google-dorking.md`, `shodan-censys.md`, `transparencia-certificados.md`, `dns-pasivo.md`, `fingerprinting-tecnologias-web.md`, `recoleccion-emails.md`, `wayback-machine.md`, `whois-registros-dominio.md`.
- **Fase 01 - Reconocimiento Activo** (6 técnicas): `descubrimiento-hosts.md`, `escaneo-puertos.md`, `fingerprinting-os-servicios.md`, `enumeracion-dns.md`, `escaneo-vulnerabilidades.md`, `deteccion-waf.md`.
- **Formato de Referencias APA**: Definida guía de formato APA 7ma edición en `AGENTS.md` con ejemplos para libros, frameworks online, herramientas/repos y notas del proyecto.

### Corregido
- **MITRE ATT&CK IDs**: Corregidos 4 IDs incorrectos (`deteccion-waf.md` T1595.001→T1595, `fingerprinting-tecnologias-web.md` T1592.004→T1592.002, `fingerprinting-os-servicios.md` T1592.001→T1592.002, `wayback-machine.md` T1593.002→T1593).
- **Clasificación**: Movido `deteccion-waf.md` de `pasivo/` a `activo/` (WAF detection requiere interacción con el target).
- **Info desactualizada**: Removida cookie `__cfduid` (deprecada por Cloudflare 2021), reemplazado `amap` (abandonado) por `nmap -sV --version-all`, corregida sintaxis de `retire.js`.
- **Comando redundante**: Corregido `-f --mtu 16` → `--mtu 16` en `descubrimiento-hosts.md`.
- **Warning faltante**: Agregada advertencia en `nmap --script exploit` (`escaneo-vulnerabilidades.md`).
- **Plataforma**: Corregido `dns-pasivo.md` de "Web" a "Multi".
- **Formato revisor**: Restaurado formato `**Herramientas**`/`**Instrucciones**` en `AGENTS.md`.

### Actualizado
- **Referencias a formato APA**: Las 14 técnicas de Fase 01 actualizadas a formato APA 7ma edición con datos reales de autores, editoriales y años.
- **Referencias a libros**: Incorporadas referencias a libros de `referencias/` en todas las técnicas (previamente solo referenciaban notas y MITRE).

## [2026-03-22]

### Añadido
- **Estructura del Inventario**: Creada la jerarquía de directorios completa (01-08) según la taxonomía definida en `AGENTS.md`.
- **Carpeta de Redundancia**: Creado el directorio `redundancia/` para almacenar versiones descartadas o duplicadas de notas de forma segura sin pérdida de información.
- **Herramienta de Diagnóstico**: Creado `compare_notes.py` para detectar inconsistencias entre `notas/` (HTML) y `notas-md/` (Markdown).
- **Heurísticas de Prioridad**: Actualizado `AGENTS.md` con reglas claras para la resolución de conflictos (Prioridad 1: Oficial, 2: Libros, 3: Notas personales).

### Analizado
- **Inconsistencias de Nombres**: Identificados archivos HTML con dobles espacios antes del hash, lo que causaba desajustes en la normalización.
- **Detección de Duplicados**: Identificada una nota redundante en `notas/` con dos versiones distintas (18K vs 19K): `DOM XSS in document write sink using source locati`.
