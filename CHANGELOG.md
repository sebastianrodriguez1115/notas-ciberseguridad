# CHANGELOG - Inventario de Técnicas de Ciberseguridad

Todos los cambios notables en este proyecto serán documentados en este archivo.

## [2026-04-29] — Sesión 13 (Lab PortSwigger XML encoding bypass + WAF bypass en inventario)

Sesión continuando la serie SQLi de PortSwigger: cambio de tipo de lab de blind a **UNION-based con WAF + bypass via XML hex entities**. Solved al primer intento. Aprovechamos para añadir al inventario dos huecos nuevos: la distinción numeric/string SQLi y la categoría completa de WAF bypass (encoding asimétrico + bypasses a nivel SQL).

### Añadido
- **`learning/portswigger/sqli-filter-bypass-xml-encoding/`** — sexto writeup en el directorio `learning/portswigger/`. Construido iterativamente:
    - `writeup.md` (10 secciones): objetivo y cambio de patrón (de cookie a body XML, de blind a UNION-based con WAF), recon del endpoint `/product/stock` con `Content-Type: application/xml`, **sondeo aritmético `3-1` para confirmar numeric SQLi sin tocar keywords del WAF** (técnica didácticamente clave: pasa por debajo del radar del WAF de patrones), confirmación del WAF con respuestas 403 "Attack detected" en `'` y `UNION`, explicación de la asimetría WAF-vs-parser (WAF inspecciona wire format, backend ve XML parseado) que habilita el bypass, construcción del bypass mínimo encodeando sólo la primera letra de las keywords (`&#x55;NION &#x53;ELECT`) más las comillas (`&#x27;`), validación con `UNION SELECT NULL` (200 OK + body con `null`) y descubrimiento bonus de que el endpoint imprime todos los rows del result set (permite extraer toda la tabla en una request), extracción con `username||'~'||password FROM users`, login admin, contramedidas específicas (parametrización, validación de tipo numeric en valores XML, WAFs que parsean el formato antes de aplicar reglas, allow-list).
    - `solved.png`: confirmación visual del lab solved.

### Actualizado
- **`inventario/03-analisis-vulnerabilidades/web/analisis-sql-injection.md`**:
    - **Bloque nuevo "Sondeo previo — numeric vs string SQLi"** al inicio de "Comandos / Ejemplos", explicando la distinción y proponiendo el test aritmético (`3-1`) y el test de comilla como sondeos complementarios. Útil contexto antes de los 6 tipos de inyección.
    - **Nueva sección 6 "WAF Bypass — Encoding asimétrico"** después de load_file. Documenta el patrón general (WAF inspecciona wire format, parser decodea), tabla de esquemas de encoding por formato del body (XML entities, JSON unicode escapes, URL-encoding, multipart Content-Transfer-Encoding, gzip), ejemplo XML completo con bypass mínimo vs agresivo, y bloque de bypasses a nivel SQL (comentarios inline `UN/**/ION`, whitespace alternativo `%09`/`%0a`/`/**/`, equivalencias semánticas `&&`/`||`/`MID`/`IIF`). Cierra con heurística de orden de prueba.
    - Referencias ampliadas con el nuevo writeup.
- **`inventario/04-explotacion/web/explotacion-sqli.md`**:
    - Sondeo aritmético `3-1` añadido al bloque "Pruebas manuales básicas" como primer test antes del bypass clásico de login.
    - Bloque XML hex entities bypass añadido después del bloque OOB, con bypass mínimo vs agresivo + bloque adicional de bypasses SQL-level (comentarios inline, whitespace alternativo, equivalencias semánticas) y heurística de orden de prueba.
    - Referencias ampliadas con el nuevo writeup.

## [2026-04-29] — Sesión 12 (Lab PortSwigger OOB + categoría OOB en inventario)

Sesión continuando la serie de blind SQLi: lab de **out-of-band interaction** (Oracle, XXE via `xmltype`). El lab no se cerró como **Solved** porque PortSwigger Academy bloquea outbound hacia cualquier dominio distinto de `*.oastify.com` (Burp Pro Collaborator, no disponible). El conocimiento técnico y el diagnóstico se capturan igualmente: la categoría OOB queda añadida al inventario como cuarta familia blind, y el writeup documenta tanto la técnica como la limitación operacional encontrada.

### Añadido
- **`learning/portswigger/blind-sqli-out-of-band/`** — quinto writeup en el directorio `learning/portswigger/`. No solved (limitación operacional), pero pedagógicamente valioso:
    - `writeup.md` (9 secciones): objetivo, motivo del cambio de motor a Oracle (XXE via `xmltype` es Oracle-específico), tabla de primitivas OOB por motor, setup de **interactsh-client** como receptor OAST gratuito (alternativa a Burp Collaborator), construcción del payload Oracle XXE pieza por pieza, **diagnóstico sistemático** ante la falta de interacciones (descarte de Burp HTTP/2 con curl, descarte de `+` vs `%20`, descarte de XXE-específico probando `UTL_HTTP.REQUEST` y `UTL_INADDR.GET_HOST_ADDRESS`, descarte de cookie no procesada), hallazgo final del **firewall de PortSwigger Academy que sólo permite `*.oastify.com`** (citado del statement del lab que pasamos por alto al empezar — lección meta sobre leer las notas completas antes de inyectar), conclusión de que el lab requiere Burp Pro, contramedidas específicas de OOB (egress filtering en el host de la DB, deshabilitar resolvers de entidades externas en parsers XML, privilegios mínimos sobre `UTL_HTTP`/`UTL_INADDR`/`xp_dirtree`).

### Actualizado
- **`inventario/03-analisis-vulnerabilidades/web/analisis-sql-injection.md`** — **nueva sección 4 "Inyección Fuera de Banda (Out-of-Band / OAST)"** insertada entre time-blind y load_file (antes el archivo cubría sólo error/boolean/time + load_file; OOB era un hueco evidente). Incluye: cuándo aplica (queries async fire-and-forget que cierran los tres canales clásicos), tabla de primitivas OOB por motor (Oracle XXE+UTL_HTTP+UTL_INADDR+DBMS_LDAP, MS SQL `xp_dirtree`, MySQL `LOAD_FILE`+`OUTFILE` Windows, PostgreSQL `COPY TO PROGRAM`), ejemplo Oracle XXE completo con explicación del orden de evaluación (`xmltype()` resuelve la entidad antes de llegar a `EXTRACTVALUE`), tabla de receptores OAST (Burp Collaborator vs interactsh vs DNSLog vs servidor propio) con coste y caso de uso, nota operacional sobre allowlists de OAST (PortSwigger Academy `*.oastify.com` only). Referencias ampliadas con el nuevo writeup.
- **`inventario/04-explotacion/web/explotacion-sqli.md`** — bloque OOB añadido a "Pruebas manuales", paralelo a los bloques error-based y time-based de sesiones anteriores. Cubre Oracle XXE + alternativas, MS SQL `xp_dirtree`, MySQL Windows. Incluye ejemplo URL-encodeado del payload XXE para cookie, comando de instalación de `interactsh-client` y nota sobre allowlists OAST en entornos de prácticas. Referencias actualizadas con los dos writeups que faltaban (info-retrieval y out-of-band).

## [2026-04-29] — Sesión 11 (Lab PortSwigger time-delays info retrieval + script de extracción)

Sesión continuando la serie de blind SQLi: del lab anterior (sólo provocar retardo) al lab "info-retrieval" donde hay que **extraer la password** de `administrator` por inferencia carácter a carácter via `CASE WHEN ... pg_sleep ... ELSE pg_sleep(0) END`. Pivote operacional clave: descartar Burp Intruder (1 thread en Community → ~6 min) y scriptear la extracción en Python con `ThreadPoolExecutor` (~1 min real medido).

### Añadido
- **`learning/portswigger/blind-sqli-time-delays-info-retrieval/`** — cuarto writeup en el directorio `learning/portswigger/`. Construido iterativamente durante la sesión:
    - `writeup.md` (8 secciones): objetivo y diferencia con el lab base, **validación de las dos ramas del `CASE` antes de extraer** (test `(1=1)` → 10s, test `(1=2)` → baseline; sin esto los falsos positivos invalidarían toda la extracción), determinación de longitud (`LENGTH(password)=20` → 10s confirma 20 chars), narrativa del pivote Burp Intruder → script Python con análisis del coste real (~6 min Community vs 67s medidos con 10 workers, sleep=5s, threshold=3s) y discusión de por qué no escala linealmente (serialización de `pg_sleep` en el pool de conexiones de la DB), resumen con diagrama Mermaid y contramedidas específicas para extracción time-based (`statement_timeout` corto como contramedida quirúrgica, rate limiting, decorrelación tiempo-de-respuesta vs tiempo-de-backend).
    - `extract.py`: script funcional autocontenido (~80 líneas). Usa `requests` + `concurrent.futures.ThreadPoolExecutor`, encodea la cookie con `urllib.parse.quote_plus` (resuelve `;` → `%3B`, `'` → `%27`, espacios → `+` de un golpe), imprime hits en streaming, parametrizable por `--url`, `--session` y `--workers`.
    - `solved.png`: confirmación visual del lab resuelto (login con la password extraída `jyuepelyogm45rdshesl`).

### Actualizado
- **`inventario/04-explotacion/web/explotacion-sqli.md`** — añadida nota operacional al final del bloque time-based: paralelismo en extracción time-based, limitación de Burp Community (1 thread), patrón `requests + ThreadPoolExecutor` con cuello de botella en el pool de conexiones de la DB, link al writeup como implementación de referencia.

## [2026-04-29] — Sesión 10 (Lab PortSwigger + enriquecimiento SQLi time-based)

Sesión de aprendizaje guiada paso a paso resolviendo el lab de PortSwigger **"Blind SQL injection with time delays"**, con captura del conocimiento operativo derivado en el inventario.

### Añadido
- **`learning/portswigger/blind-sqli-time-delays/`** — tercer writeup en el directorio `learning/portswigger/`. Construido iterativamente durante la sesión:
    - `writeup.md` (8 secciones): objetivo, baseline cuantificado (~185ms estable), descarte explícito de canales más cómodos (test `'` suelto sin error reflejado → no error-based; `AND '1'='1` vs `AND '1'='2` con respuestas idénticas → no boolean-based) que justifica el salto a tiempo, payload final con stacked queries (`x'%3BSELECT+pg_sleep(10)--`) con explicación pieza por pieza, **detalle didáctico del `;` como delimitador de cookies y la necesidad de URL-encodearlo como `%3B`** (gotcha específico de inyectar en headers Cookie), tabla de primitivos de retardo por motor (PG `pg_sleep`, MySQL `SLEEP`, MS SQL `WAITFOR DELAY`, Oracle `dbms_pipe.receive_message`, SQLite con queries pesadas), variantes equivalentes (concat `||`, cláusula `AND`), resumen con diagrama Mermaid y contramedidas (statement_timeout, deshabilitar multi-statement, monitoreo de latencia anómala).
    - `solved.png`: confirmación visual del lab resuelto al primer intento.

### Actualizado
- **`inventario/03-analisis-vulnerabilidades/web/analisis-sql-injection.md`** — sección 3 "Inyección Ciega Basada en Tiempo" reescrita y ampliada. Antes solo listaba MySQL `SLEEP` y el patrón complejo PostgreSQL `CASE WHEN ... pg_sleep ... ELSE pg_sleep END`; ahora documenta tabla de primitivos por motor (PG/MySQL/MSSQL/Oracle/SQLite), las tres formas de inyectar el sleep (stacked queries `;`, concat `||`, cláusula `AND`) según qué tolere el sink, el patrón `CASE WHEN` reservado explícitamente para inferencia bit a bit, ejemplos de inferencia en PG/MySQL/MS SQL, y nota sobre el `;` URL-encoded cuando el sink es header Cookie. Mención del baseline como pre-requisito metodológico. Referencias ampliadas con el nuevo writeup.
- **`inventario/04-explotacion/web/explotacion-sqli.md`** — bloque "Pruebas manuales básicas" extendido con un nuevo bloque dedicado a payloads time-based, paralelo al de error-based añadido en sesión 9. Cubre los 5 motores principales, payload de inferencia con `CASE WHEN`, gotcha del `;` URL-encoded en cookies, y ejemplo de `sqlmap --technique=T --time-sec=5`. Referencias con enlace al writeup.

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
