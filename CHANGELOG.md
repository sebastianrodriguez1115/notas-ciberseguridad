# CHANGELOG - Inventario de Técnicas de Ciberseguridad

Todos los cambios notables en este proyecto serán documentados en este archivo.

## [2026-04-29] — Sesión 9 (Lab PortSwigger + enriquecimiento SQLi error-based)

Sesión de aprendizaje guiada paso a paso resolviendo el lab de PortSwigger **"Visible error-based SQL injection"**, con captura del conocimiento operativo derivado en el inventario.

### Añadido
- **`learning/portswigger/visible-error-based-sql-injection/`** — segundo writeup en el directorio `learning/portswigger/`. Construido iterativamente durante la sesión:
    - `writeup.md` (8 secciones): objetivo, provocación del primer error con la nota didáctica `'` solo vs `' --` (la trampa típica donde el `--` cierra y comenta — no rompe — la query), salto de error de sintaxis a exfiltración con la técnica `CAST(<subquery> AS int)`, descubrimiento del **truncado de la cookie a 60 chars server-side** y workaround con concatenación `||` para meter el `CAST` dentro del string del `WHERE`, lectura de `users.password` con `LIMIT 1`, login como administrator, resumen de la cadena con diagrama Mermaid, contramedidas y referencias APA.
    - `solved.png`: confirmación visual del lab resuelto.

### Actualizado
- **`inventario/03-analisis-vulnerabilidades/web/analisis-sql-injection.md`** — sección 1 "Inyección Basada en Error" reescrita y ampliada. Antes solo listaba el clásico MySQL `COUNT/GROUP BY/FLOOR(RAND())`; ahora documenta el primitivo más limpio (`CAST` en PostgreSQL/SQLite que vuelca el valor en `ERROR: invalid input syntax for type integer`) con sus equivalentes por motor (`CONVERT` en MS SQL, `TO_NUMBER` en Oracle, `extractvalue()` XPath en MySQL), añade la variante con concatenación `||` para casos con límite de longitud en el punto de inyección, y deja el payload `COUNT/GROUP BY` como fallback explícito. Referencias ampliadas con PortSwigger Blind SQLi y enlace al writeup como evidencia.
- **`inventario/04-explotacion/web/explotacion-sqli.md`** — bloque "Pruebas manuales básicas" extendido de un solo payload (MySQL clásico) a cinco variantes comentadas: PostgreSQL/SQLite con `CAST AND` clásico, PostgreSQL/Oracle/SQLite con concatenación `||`, MS SQL con `CONVERT/TOP 1`, MySQL con `extractvalue`, y el `COUNT/GROUP BY` original como fallback. Referencias con enlace al writeup.

## [2026-04-28] — Sesión 8 (Lab PortSwigger + enriquecimiento CSRF)

Sesión de aprendizaje guiada paso a paso resolviendo el lab de PortSwigger **"SameSite Lax bypass via cookie refresh"**, con captura del conocimiento operativo derivado en el inventario.

### Añadido
- **`learning/portswigger/samesite-lax-bypass-via-cookie-refresh/`** — primer writeup en el directorio `learning/portswigger/`. Construido iterativamente durante la sesión:
    - `writeup.md` (~600 líneas, 10 secciones): objetivo, reconocimiento del flujo OAuth con diagrama de secuencia Mermaid y 5 observaciones extraídas del Burp history, fundamentos de CSRF con verificación de los 3 ingredientes, explicación de SameSite (los 3 modos + excepción Lax+POST de Chrome), construcción incremental del exploit en 4 versiones (V1 ingenuo → V4 con click programático en `onload`), entrega, troubleshooting, contramedidas y referencias APA.
    - `http_history.xml` y `change-email.xml`: capturas Burp del flujo OAuth y del POST legítimo, citadas como evidencia en el writeup.
    - `exploit.html`: payload V4 final listo para subir al exploit server.
    - `solved.png`: confirmación visual de que el lab quedó resuelto al primer intento.

### Actualizado
- **`inventario/03-analisis-vulnerabilidades/web/analisis-csrf.md`** — añadida sección **Bypasses de SameSite** con dos técnicas documentadas (ventana Lax+POST de 2 min en Chrome, cookie refresh via OAuth/SSO) y referencia breve a otros bypasses conocidos (method override, client-side redirect, sibling domain). Sección de Contramedidas reforzada con guía explícita: tokens anti-CSRF como defensa principal (no `SameSite`), fijar `SameSite` explícito para evitar el modo default que activa Lax+POST, no emitir cookies nuevas en endpoints navegables sin gesto del usuario. Referencias ampliadas con PortSwigger, Chromium SameSite Updates, MDN y OWASP CSRF Cheat Sheet.

## [2026-04-28] — Sesión 7 (Pasada de consistencia)

Auditoría y limpieza del warehouse para dejarlo en estado íntegro y honesto, motivada por el descubrimiento de **96 archivos** con referencias rotas a `notas-md/` (directorio que ya no existe en disco). El objetivo: que cualquier agente que consulte el inventario reciba información verificable y un mapa de navegación íntegro.

### Limpieza
- **Refs rotas a `notas-md/` eliminadas en 96 archivos del inventario**. `notas-md/` fue el export Notion usado para bootstrapear el inventario en 2025; el contenido relevante ya está absorbido en los archivos `analisis-*.md` / `explotacion-*.md` / etc. Las refs apuntando a `notas-md/HNotes/...` se eliminaron mecánicamente con `sed '/^- Notas del proyecto: notas-md\//d'`, preservando intactas las referencias bibliográficas a libros, MITRE, HackTricks y demás. Las 2 refs vivas a `learning/tryhackme/...` (verificadas como archivos existentes) se conservaron.
- **`inventario/TEMPLATE.md`** — removida la línea de ejemplo `Para notas: Notas del proyecto: notas-md/ruta/al/archivo.md` del comentario para redactor, evitando que se propague el patrón muerto a archivos nuevos.

### Actualizado
- **`AGENTS.md`** — reescrita la sección `Fuentes de Información` para reflejar la realidad actual. La nueva sección 1 describe `inventario/` como fuente canónica (165 archivos) con la jerarquía de 3 niveles de `INDEX.md` explícitamente documentada (root → fase → subcategoría). Se añadió una nota histórica explicando el origen y archivado de `notas-md/`. Actualizadas además: protocolo de búsqueda local (paso 1), `Heurísticas de Prioridad` (Prioridad 3), `Resolución de Conflictos` (duplicados), instrucciones del agente `investigador`, y `Paso 1 — Investigación` del Workflow Probado, todas para dejar de referenciar el directorio inexistente.

### Añadido
- **`inventario/07-fundamentos/sistemas/INDEX.md`** — añadida fila `Windows API para Hacking | Intermedia` que existía en el dir desde antes pero no estaba listada en el INDEX.
- **`inventario/07-fundamentos/compliance/INDEX.md`** — creado placeholder informativo enumerando tópicos esperados (CVSS v3/v4, OWASP ASVS, NIST CSF, ISO 27001/27002, MITRE D3FEND, GDPR). El dir existía vacío sin INDEX, rompiendo el contrato de la jerarquía navegable.
- **`inventario/07-fundamentos/INDEX.md`** — añadida entrada para la subcategoría `Compliance` marcada como `(pendiente de contenido)`.

### Verificado post-pass
Auditoría de integridad completa, todos los chequeos limpios:
- 0 referencias rotas a `notas-md/` en el inventario.
- 0 desincronizaciones tier-3 (todos los archivos `*.md` están listados en su INDEX de subcategoría).
- 0 desincronizaciones tier-2 (todas las subcategorías están listadas en el INDEX de su fase).
- 0 directorios sin INDEX.
- 166 archivos `.md` totales (165 previos + 1 nuevo en compliance).

## [2026-04-07] — Sesión 6 (FINALIZACIÓN DEL PROYECTO)

### Añadido
- **Fase 06 - Frameworks y Herramientas** — 4 guías avanzadas:
    - **burp-suite/**: `configuracion-uso-avanzado.md` (Scope, Intruder, Macros de sesión).
    - **metasploit/**: `metasploit-avanzado.md` (Workspaces, Resource files, Post-exploitation).
    - **powershell-empire/**: `empire-framework.md` (Listeners, Stagers, C2 workflow).
    - **otros/**: `bloodhound.md` (SharpHound, Graph theory, AD attack paths).
- **Fase 07 - Fundamentos** — 4 guías base:
    - **redes/**: `modelo-osi-tcp-ip.md` (PDU, Three-Way Handshake, Comandos de diagnóstico).
    - **sistemas/**: `linux-arquitectura-permisos.md` (FHS, Permisos rwx, SUID/SGID, Gestión de procesos).
    - **sistemas/**: `windows-arquitectura-ad.md` (Procesos críticos,lsass, Kerberos/NTLM, Fundamentos AD).
    - **criptografia/**: `hashing-codificacion.md` (Diferencias Codificación/Hash/Cifrado, Algoritmos, Herramientas).
- **Fase 08 - Forense y DFIR** — 4 guías de investigación:
    - **analisis-forense/**: `artefactos-windows-host.md` (Prefetch, ShimCache, LNK, Eric Zimmerman's tools).
    - **analisis-forense/**: `volatility-memoria.md` (Adquisición RAM, netscan, malfind, procdump).
    - **incident-response/**: `metodologia-picerl.md` (Fases SANS, Contención vs Erradicación, SIEM/EDR).
    - **malware-analysis/**: `analisis-estatico-dinamico.md` (Hashing, Strings, PE analysis, YARA rules, Sandboxing).
- **Fase 09 - Sistema de Índices** — Implementación de navegación recursiva:
    - Creado `inventario/INDEX.md` maestro con enlaces a todas las fases.
    - Creados archivos `INDEX.md` en cada una de las 8 carpetas de fase y sus 20 subcarpetas de categoría.
    - Tablas de referencia rápida con MITRE IDs y dificultad en cada nivel de subcategoría.

### Actualizado
- **Estado del Proyecto**: Todas las fases del roadmap original han sido completadas con éxito.
- **TASKS.md**: Archivo eliminado tras la consecución de todos los objetivos.

---

## [2026-03-27] — Sesión 5

### Añadido
- **Fase 05 - Post-Explotación** — 20 técnicas nuevas:
    - **privilege-escalation/linux/** (7): `suid-sgid.md`, `abuso-sudo.md`, `abuso-cron-jobs.md`, `capabilities-linux.md`, `kernel-exploits-privesc-linux.md`, `nfs-no-root-squash.md`, `enumeracion-privesc-linux.md`
    - **privilege-escalation/windows/** (5): `token-impersonation.md`, `credential-dumping.md`, `abuso-servicios-windows.md`, `abuso-tareas-programadas.md`, `enumeracion-privesc-windows.md`
    - **persistencia/** (3): `persistencia-linux.md`, `persistencia-windows.md`, `web-shells.md`
    - **lateral-movement/** (3): `pass-the-hash.md`, `pivoting-tunneling.md`, `ejecucion-remota-windows.md`
    - **exfiltracion/** (2): `canales-encubiertos.md`, `transferencia-archivos.md`

### Corregido
- Edición incorrecta del libro de Allen en 7 archivos: corregido de "(4th ed.)" a "(2nd ed.)" según el PDF existente en `referencias/`
- Formato de entrada de herramientas LOLBAS en `enumeracion-privesc-linux.md`

### Actualizado
- Tabla de libros en `AGENTS.md` ordenada alfabéticamente por título

---

## [2026-03-24] — Sesión 4

### Añadido
- **Biblioteca de Referencias**: Incorporados 17 nuevos PDFs a la carpeta `referencias/` (total 33 libros), incluyendo *The Web Application Hacker's Handbook*, *Black Hat GraphQL* y *Wireshark 2 Cookbook*.
- **AGENTS.md**: Actualizada la tabla de fuentes de información para incluir los 33 libros categorizados por área técnica.

### Actualizado (Enriquecimiento Técnico)
- **Fase 03 - Análisis de Vulnerabilidades Web** (4 técnicas clave):
    - `analisis-xss.md`: Añadidos contextos de inyección (HTML, Atributos, JS), DOM-Based XSS y técnicas de evasión de filtros.
    - `analisis-ssrf.md`: Añadida exfiltración de metadatos de Cloud (AWS, GCP, DigitalOcean) y bypasses de filtros de IP/DNS.
    - `analisis-sql-injection.md`: Añadidas metodologías para Blind SQLi (Boolean/Time-based) y lectura de archivos con `load_file`.
    - `analisis-lfi-rfi.md`: Añadidos vectores avanzados con PHP Wrappers y técnica de RCE vía Log Poisoning.

### Corregido
- **Estandarización**: Restaurada la consistencia en los campos `Fase`, `Plataforma` y `Dificultad` en las técnicas web enriquecidas para mantener la compatibilidad con el sistema de índices.

---

## [2026-03-23] — Sesión 3

### Añadido
- **Fase 02 - Enumeración Servicios** (3 técnicas nuevas): `enumeracion-ldap.md`, `enumeracion-smtp.md`, `enumeracion-oracle.md`.
- **Fase 02 - Enumeración Servicios** (9 técnicas nuevas): `enumeracion-postgresql.md`, `enumeracion-redis.md`, `enumeracion-vnc.md`, `enumeracion-telnet.md`, `enumeracion-mongodb.md`, `enumeracion-docker.md`, `enumeracion-kubernetes.md`, `enumeracion-elasticsearch.md`, `enumeracion-memcached.md`, `enumeracion-rabbitmq.md`.
- **Fase 02 - Enumeración Red** (2 técnicas nuevas): `enumeracion-kerberos.md`, `enumeracion-ipmi.md`.
- **Fase 03 - Análisis de Vulnerabilidades Scanning** (2 técnicas): `analisis-nmap-nse.md`, `escaneo-openvas-gvm.md`.
- **Fase 03 - Análisis de Vulnerabilidades Web** (6 técnicas): `analisis-sql-injection.md`, `analisis-xss.md`, `analisis-csrf.md`, `analisis-idor.md`, `analisis-lfi-rfi.md`, `analisis-seguridad-cabeceras.md`.
- **Fase 03 - Análisis de Vulnerabilidades Sistema** (4 técnicas): `analisis-parches-windows.md`, `analisis-permisos-linux.md`, `analisis-servicios-mal-configurados.md`, `analisis-software-obsoleto.md`.
- **Fase 03 - Análisis de Vulnerabilidades Web** (8 técnicas adicionales): `analisis-cors.md`, `analisis-ssrf.md`, `analisis-ssti.md`, `analisis-command-injection.md`, `analisis-xxe.md`, `analisis-deserialization.md`, `analisis-open-redirect.md`, `analisis-nessus.md`.
- **Fase 04 - Explotación Web** (7 técnicas): `explotacion-sqli.md`, `explotacion-nosqli.md`, `explotacion-deserialization.md`, `explotacion-fileupload.md`, `explotacion-jwt.md`, `explotacion-auth-bypass-oauth.md`, `explotacion-cms-wordpress.md`.
- **Fase 04 - Explotación Red** (5 técnicas): `explotacion-arp-spoofing.md`, `explotacion-mitm-responder.md`, `explotacion-mitm6.md`, `explotacion-smb-relay.md`, `explotacion-adcs-relay.md`.
- **Fase 04 - Explotación Sistema** (6 técnicas): `explotacion-buffer-overflow-stack.md`, `explotacion-eternalblue.md`, `explotacion-shellshock.md`, `explotacion-zerologon.md`, `explotacion-kernel-linux.md`, `explotacion-kernel-windows.md`.
- **Fase 04 - Explotación Client-Side** (3 técnicas): `explotacion-msfvenom.md`, `explotacion-phishing-tecnico.md`, `explotacion-process-injection.md`.
- **Fase 04 - Explotación Credenciales** (3 técnicas): `explotacion-hash-cracking.md`, `explotacion-brute-force-advanced.md`, `explotacion-password-spraying.md`.
- **Template**: Creado `inventario/TEMPLATE.md` con estructura exacta, ejemplos de formato y notas para el redactor en comentario HTML.
- **Idioma y Ortografía**: Añadida sección en `AGENTS.md` requiriendo acentos y ortografía correcta en español.
- **Referencia al Template**: Actualizado `AGENTS.md` para apuntar a `inventario/TEMPLATE.md` como lectura obligatoria antes de crear archivos.

### Corregido (Fase 02 — post-review de 12 archivos nuevos)
- **MITRE ATT&CK IDs**: Corregidos 8 IDs incorrectos: redis/mongodb/elasticsearch/memcached T1595→T1046, telnet/ipmi/docker T1021.002→T1046, postgresql T1210→T1046. Añadidos T1558.003 y T1558.004 a kerberos.
- **Dificultad no estándar**: Corregidos 6 archivos: kerberos/ipmi/docker "Media"→"Intermedia", postgresql "Básica/Media"→"Intermedia", telnet "Muy Básica"→"Básica", kubernetes "Media/Alta"→"Avanzada".
- **Plataforma no estándar**: Corregidos 7 archivos que usaban listas o paréntesis ("Linux, Windows", "Hardware (...)") → "Multi".
- **Referencias faltantes**: Añadidas citas a libros de `referencias/` en los 12 archivos (Allen 2022, Harper et al. 2018).
- **VNC hashcat**: Corregido modo -m 3000 (LM hash) → uso de `vncpwd` para descifrado de contraseñas VNC.

### Corregido (Fase 03 — post-review de 12 archivos iniciales)
- **Campo Fase faltante**: Añadido `- **Fase**: Análisis de Vulnerabilidades` a los 12 archivos.
- **Orden de Clasificación**: Corregido de Dificultad→Plataforma→MITRE a Fase→MITRE→Plataforma→Dificultad en 12 archivos.
- **Formato de dos puntos**: Corregido `**Campo:**` → `**Campo**:` en 12 archivos.
- **Herramientas sin formato**: Añadido bold, módulos entre paréntesis y descripción con guión largo en 12 archivos.
- **MITRE ATT&CK IDs**: analisis-csrf T1595→T1185, analisis-idor T1595→T1213, analisis-seguridad-cabeceras T1595→T1595.002, analisis-servicios-mal-configurados T1068→T1078.
- **Autor incorrecto**: escaneo-openvas-gvm.md Velu V. (2017)→Allen M. (2022) para Mastering Kali Linux.

---

## [2026-03-23] — Sesión 2

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
