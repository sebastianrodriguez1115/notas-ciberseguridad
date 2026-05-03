# Inventario de Técnicas de Ciberseguridad - AGENTS.md

## Protocolo de Interacción (Uso del Agente)

Para cualquier consulta o tarea solicitada por el usuario, el agente debe seguir este flujo de trabajo:

1. **Búsqueda Local Primero**: Agotar siempre las fuentes internas antes de recurrir a Internet.
   - Consultar el `inventario/` existente para coherencia y para detectar contenido relacionado o duplicados antes de añadir.
   - Utilizar el motor `rag` para extraer información de los libros en `referencias/`.
2. **Recurso a la Web**: Solo se utilizarán herramientas de búsqueda externa (`google_web_search`, `web_fetch`) si la información no se encuentra localmente o si se requiere validación de una fuente oficial (Priority 1).
3. **Mantenimiento**: Si se descubre información relevante en la web que no está en el inventario, el agente debe proponer su incorporación.

## Objetivo

Construir un inventario estructurado y completo de técnicas de ciberseguridad, organizado por fases del ciclo de penetration testing, cubriendo desde reconocimiento hasta post-explotación.

## Fuentes de Información

### 1. `inventario/` — Conocimiento estructurado del proyecto (fuente canónica)

Taxonomía de **165 archivos Markdown** (124 técnicas + 40 INDEX + 1 TEMPLATE) organizados por fases de pentest (`01-reconocimiento` → `08-forense-dfir`, más `06-frameworks-herramientas` y `07-fundamentos` como soportes). Cada archivo sigue `inventario/TEMPLATE.md` con dos perfiles de uso:

- **Técnicas y herramientas concretas**: usan las 6 secciones obligatorias (Descripción → Clasificación → Herramientas → Comandos / Ejemplos → Contramedidas → Referencias).
- **Contenido conceptual o metodológico** (modelos teóricos como OSI/TCP-IP, ciclos como PICERL, marcos teóricos): secciones obligatorias reducidas (Título → Descripción → Clasificación → Referencias). Las secciones Herramientas, Comandos / Ejemplos y Contramedidas son opcionales y pueden sustituirse por secciones propias relevantes al tema.
- **Valores compuestos en Fase**: las técnicas o herramientas que genuinamente cruzan fases (BloodHound, enumeración Kerberos) pueden listar varios valores separados por coma+espacio (ej. `Reconocimiento, Post-Explotación`). Plataforma sigue siendo estricta: un valor o `Multi`.

La navegación se hace vía la red jerárquica de `INDEX.md`:

- **Tier 1 (root)** — `inventario/INDEX.md`: TOC maestro de las 8 fases.
- **Tier 2 (fase)** — `inventario/0X-fase/INDEX.md`: descripción de la fase + lista de subcategorías + backlink al maestro.
- **Tier 3 (subcategoría)** — `inventario/0X-fase/<subcat>/INDEX.md`: tabla `Técnica | MITRE ID | Dificultad` + backlink a la fase.

Esta es la fuente de verdad del proyecto y debe consultarse **antes** que cualquier fuente externa.

> **Nota histórica**: el inventario fue bootstrapeado en 2025 a partir de `notas-md/` (export de Notion con ~222 archivos: INE Courses, HNotes, Burp Suite Labs, TryHackMe). Ese export ya no se mantiene en el repo — el contenido relevante fue absorbido al inventario y las referencias originales en los archivos `análisis-*.md`/etc. apuntando a `notas-md/...` se eliminaron en una pasada de consistencia el 2026-04-28. Al investigar coverage de un tema, partir del inventario actual.

### 2. `referencias/` — Libros de referencia (34 PDFs)

| Libro | Área |
|-------|------|
| Advanced Persistent Threat Hacking | APTs y post-explotación |
| Begin Ethical Hacking with Python | Scripting ofensivo (Python) |
| Black Hat GraphQL | Seguridad de APIs / GraphQL |
| Burp Suite Essentials | Pentesting Web (Herramientas) |
| Complete Guide to Shodan | OSINT / Reconocimiento |
| CompTIA Security+ Certification Guide | Fundamentos de seguridad |
| Computer Security Fundamentals | Fundamentos de seguridad |
| Crypto 101 | Criptografía |
| Digital Forensics and Incident Response | DFIR / Análisis forense |
| Foundations of Python Network Programming | Redes con Python |
| Gray Hat Hacking | Hacking ofensivo/defensivo |
| Hands-On AWS Penetration Testing | Pentesting Cloud (AWS) |
| Honeypots and Routers | Redes / Defensa activa |
| Kali Revealed | Administración de Kali Linux |
| Linux Basics for Hackers | Linux para hacking |
| Linux Firewalls | Seguridad de red / Defensiva |
| Mastering Kali Linux for Advanced Penetration Testing | Pentesting avanzado |
| Metasploit for Beginners | Frameworks de explotación |
| Metasploit Penetration Testing Cookbook | Frameworks de explotación |
| Modern Web Penetration Testing | Pentesting Web |
| Network Analysis Using Wireshark 2 Cookbook | Análisis de tráfico de red |
| Network Attacks and Exploitation | Pentesting de red |
| Network Security Through Data Analysis | Análisis de seguridad y monitoreo |
| Nmap Network Exploration and Security Auditing Cookbook | Escaneo y auditoría de red |
| Practical Mobile Forensics | Forense móvil |
| Social Engineering - The Art of Human Hacking | Ingeniería social |
| TCP/IP in 24 Hours | Fundamentos de redes |
| The Hacker Playbook 3 | Pentesting práctico |
| The Tangled Web | Pentesting Web (Seguridad de navegadores) |
| The Web Application Hacker's Handbook | Pentesting Web (Referencia principal) |
| Web Application Security (Andrew Hoffman) | Pentesting Web |
| Web Hacking 101 | Pentesting Web (Vulnerabilidades reales) |
| No SQL, No Injection? Examining NoSQL Security (Ron et al., IBM, 2015) | Seguridad NoSQL / Inyecciones |
| Web Penetration Testing with Kali Linux | Pentesting Web |

### 3. Internet — Frameworks, Bases de Conocimiento y Recursos Abiertos

#### Frameworks y Taxonomias de Ataques

| Recurso | URL | Descripción |
|---------|-----|-------------|
| **MITRE ATT&CK** | https://attack.mitre.org/ | Base de conocimiento de tácticas y técnicas adversarias basada en observaciones reales. Estructura matriz por fases (Initial Access → Impact). Referencia principal para mapear técnicas. |
| **MITRE ATLAS** | https://atlas.mitre.org/ | Extensión de ATT&CK para ataques contra sistemas de IA/ML. |
| **CAPEC** | https://capec.mitre.org/ | Common Attack Pattern Enumeration and Classification. Catalogo de patrones de ataque con enfoque en aplicaciones. Complementa ATT&CK a nivel de implementacion. |
| **CWE** | https://cwe.mitre.org/ | Common Weakness Enumeration. Lista de debilidades de software/hardware que pueden ser explotadas. |
| **Cyber Kill Chain** | https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html | Modelo lineal de 7 fases de un ciberataque (Lockheed Martin). |

#### Estándares de Seguridad Web

| Recurso | URL | Descripción |
|---------|-----|-------------|
| **OWASP Top 10** | https://owasp.org/www-project-top-ten/ | Las 10 vulnerabilidades web mas críticas. Referencia fundamental para seguridad de aplicaciones. |
| **OWASP Web Security Testing Guide (WSTG)** | https://owasp.org/www-project-web-security-testing-guide/ | Guía completa de testing de seguridad web con metodología paso a paso. |
| **OWASP API Security Top 10** | https://owasp.org/API-Security/ | Top 10 riesgos de seguridad en APIs. |
| **OWASP Mobile Top 10** | https://owasp.org/www-project-mobile-top-10/ | Top 10 riesgos de seguridad en aplicaciones moviles. |
| **OWASP Cheat Sheet Series** | https://cheatsheetseries.owasp.org/ | Cheat sheets de contramedidas para desarrolladores. |

#### Bases de Datos de Vulnerabilidades y Exploits

| Recurso | URL | Descripción |
|---------|-----|-------------|
| **NVD (National Vulnerability Database)** | https://nvd.nist.gov/ | Repositorio gubernamental de EE.UU. con datos de vulnerabilidades (SCAP). Incluye scoring CVSS. |
| **CVE Program** | https://www.cve.org/ | Identificadores estándar para vulnerabilidades conocidas. |
| **CVE Details** | https://www.cvedetails.com/ | Agregador de CVEs con busqueda avanzada, estadísticas y feeds. |
| **Exploit-DB** | https://www.exploit-db.com/ | Base de datos de exploits, shellcode y papers de seguridad. Mantenida por OffSec. |
| **CISA KEV** | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | Catalogo de vulnerabilidades activamente explotadas (Known Exploited Vulnerabilities). |

#### Knowledge Bases y Cheatsheets Ofensivos

| Recurso | URL | Descripción |
|---------|-----|-------------|
| **HackTricks** | https://hacktricks.wiki/ | Wiki extensiva de técnicas de hacking, CTFs, privilege escalation, AD attacks. Recurso central para pentesting. |
| **PayloadsAllTheThings** | https://github.com/swisskyrepo/PayloadsAllTheThings | Repositorio de payloads y bypasses para seguridad web y pentesting. Organizado por tipo de vulnerabilidad. |
| **GTFOBins** | https://gtfobins.github.io/ | Binarios Unix que permiten bypass de restricciones locales (sudo, SUID, capabilities). Esencial para privesc Linux. |
| **LOLBAS** | https://lolbas-project.github.io/ | Living Off The Land Binaries, Scripts and Libraries para Windows. Equivalente de GTFOBins para Windows. |
| **LOLAD** | https://lolad-project.github.io/ | Living Off The Land in Active Directory. Técnicas de explotación de AD con herramientas nativas. |
| **RevShells** | https://www.revshells.com/ | Generador de reverse shells en múltiples lenguajes. |
| **CyberChef** | https://gchq.github.io/CyberChef/ | Herramienta web para encoding/decoding, crypto, análisis de datos. |

#### Metodologias de Pentesting

| Recurso | URL | Descripción |
|---------|-----|-------------|
| **PTES** | http://www.pentest-standard.org/ | Penetration Testing Execution Standard. Define el ciclo completo de un pentest. |
| **OSSTMM** | https://www.isecom.org/OSSTMM.3.pdf | Open Source Security Testing Methodology Manual. Metodología peer-reviewed para security testing. |
| **NIST SP 800-115** | https://csrc.nist.gov/publications/detail/sp/800-115/final | Guía técnica de NIST para pruebas de seguridad. Estándar para entornos regulados. |

#### Compliance y Defensive Frameworks

| Recurso | URL | Descripción |
|---------|-----|-------------|
| **NIST CSF** | https://www.nist.gov/cyberframework | Cybersecurity Framework (Identify, Protect, Detect, Respond, Recover). |
| **MITRE D3FEND** | https://d3fend.mitre.org/ | Base de conocimiento de contramedidas defensivas. Complemento defensivo de ATT&CK. |
| **MITRE Shield / Engage** | https://engage.mitre.org/ | Framework de defensa activa y cyber deception. |

---

## Taxonomia del Inventario

El inventario se organiza siguiendo las fases del penetration testing (alineado con PTES/MITRE ATT&CK):

```
inventario/
├── 01-reconocimiento/
│   ├── pasivo/              # OSINT, Shodan, Censys, Google Dorking, certificados
│   └── activo/              # nmap, dnsrecon, port scanning, service detection
├── 02-enumeración/
│   ├── web/                 # HTTP, directorios, tecnologías, CMS
│   ├── red/                 # SMB, SNMP, NFS, DNS
│   ├── servicios/           # SSH, FTP, MySQL, MSSQL, RDP, WinRM
│   └── fuzzing/             # ffuf, gobuster, wordlists
├── 03-análisis-vulnerabilidades/
│   ├── scanning/            # Nessus, OpenVAS, nmap scripts
│   ├── web/                 # SQLi, XSS, CSRF, CORS, SSRF, File Inclusion
│   └── sistema/             # CVEs conocidos, misconfigurations
├── 04-explotación/
│   ├── web/                 # inyecciones, auth bypass, deserialization
│   ├── red/                 # MITM, relay attacks, protocol abuse
│   ├── sistema/             # buffer overflow, kernel exploits, shellshock, eternalblue
│   ├── client-side/         # payloads, msfvenom, PE injection, phishing
│   └── credenciales/        # brute force, hash cracking, password spraying
├── 05-post-explotación/
│   ├── privilege-escalation/
│   │   ├── linux/           # SUID, cron, capabilities, kernel exploits
│   │   └── windows/         # token manipulation, UAC bypass, services
│   ├── persistencia/        # backdoors, scheduled tasks, registry
│   ├── lateral-movement/    # pivoting, port forwarding, pass-the-hash
│   └── exfiltracion/        # data staging, covert channels
├── 06-frameworks-herramientas/
│   ├── metasploit/          # modules, msfvenom, resource scripts
│   ├── burp-suite/          # proxy, scanner, intruder, repeater
│   ├── powershell-empire/   # agents, stagers, modules
│   └── otros/               # netcat, searchsploit, CyberChef, pspy
├── 07-fundamentos/
│   ├── criptografía/        # hashing, encryption, PKI, JWT
│   ├── redes/               # OSI, TCP/IP, subnetting, firewalls
│   ├── sistemas/            # Linux commands, Windows commands, AD
│   └── compliance/          # CVSS, GRC frameworks
└── 08-forense-dfir/
    ├── análisis-forense/    # disk, memory, mobile, network forensics
    ├── incident-response/   # containment, eradication, recovery
    └── malware-analysis/    # static, dynamic, yara rules
```

## Idioma y Ortografía

Todo el contenido del inventario debe estar escrito en español con ortografía correcta, incluyendo acentos (á, é, í, ó, ú), eñes (ñ) y signos de puntuación invertidos (¿, ¡) donde corresponda. Ejemplos: "Descripción", "Clasificación", "Técnica", "contraseña", "enumeración", "gestión", "configuración", "básica", etc.

## Formato de cada Técnica

Cada técnica del inventario se documenta como un archivo Markdown siguiendo el template de referencia en **`inventario/TEMPLATE.md`**. Ese archivo contiene la estructura exacta, ejemplos de formato para cada campo y notas detalladas para el redactor en un bloque de comentario HTML al final. **Antes de crear o editar cualquier archivo del inventario, leer el template completo.**

La estructura resumida (perfil "técnica concreta") es:

```markdown
---
title: Nombre de la Técnica
slug: nombre-tecnica
aliases: [Alias 1, Alias 2]
fase: [Reconocimiento]
plataforma: Multi
dificultad: Intermedia
mitre: [T1046]
related: [otro-slug-relacionado]
learning_refs: [portswigger/lab-relacionado]
---

# Nombre de la Técnica

## Descripción
Qué es y para qué se usa.

## Herramientas
- Herramienta 1 — uso básico
- Herramienta 2 — uso básico

## Comandos / Ejemplos
Ejemplos prácticos con comandos reales.

## Contramedidas
Cómo defenderse de esta técnica.

## Referencias
- Referencias en formato APA 7ma edición (ver guía de formato abajo).
```

### Schema del frontmatter YAML

Bloque obligatorio al inicio de TODOS los archivos técnicos. Es la fuente única de verdad para metadata. La sección antigua `## Clasificación` en el body fue eliminada el 2026-05-03 (Sprint 1 del plan de discoverabilidad). Campos:

| Campo | Tipo | Requerido | Notas |
|---|---|---|---|
| `title` | string | sí | Nombre humano. Coincide con el H1. |
| `slug` | string | sí | Identificador estable, único en todo el inventario, kebab-case. Usar acrónimo establecido cuando exista (sqli, xss, csrf, etc.). |
| `aliases` | array de strings | sí (puede ser `[]`) | Variantes ES/EN y acrónimos para búsqueda. |
| `fase` | array de strings | sí | SIEMPRE array, aún con un único valor. Enums: Reconocimiento \| Enumeración \| Análisis de Vulnerabilidades \| Explotación \| Post-Explotación \| Fundamentos \| Forense y DFIR. |
| `plataforma` | string | sí | Un valor: Linux \| Windows \| Web \| Red \| Multi. |
| `dificultad` | string | sí | Un valor: Básica \| Intermedia \| Avanzada. |
| `mitre` | array de strings | sí | SIEMPRE array. IDs `T\d{4}(\.\d{3})?` con sub-técnica si aplica. |
| `related` | array de slugs | opcional, default `[]` | Slugs de otros archivos. NO paths. Validador resuelve a path. |
| `learning_refs` | array de paths | opcional, default `[]` | Paths relativos a `learning/` apuntando a directorios con `writeup.md`. |

### Slug = nombre de archivo

Convención canónica: `slug = filename sin extensión`. Por ejemplo `analisis-sqli.md` tiene `slug: analisis-sqli`. Esto se deriva automáticamente en `scripts/migrate_frontmatter.py` y se preserva si renombras vía `git mv`.

### Pares cross-fase

Cuando una técnica tiene archivo de análisis (Fase 03) y de explotación (Fase 04) sobre el mismo tópico:
- Mismo acrónimo del tema en el nombre de archivo: `analisis-sqli.md` ↔ `explotacion-sqli.md` (la convención de naming garantiza esto).
- Sus slugs heredan los nombres de archivo: `analisis-sqli` y `explotacion-sqli`. No hay colisión porque los nombres ya son distintos por el prefijo de acción.
- Listarse mutuamente en `related:` para que la cross-referencia sea explícita.

### Único conflicto operacional

Dos archivos con el mismo nombre en distintos directorios (ej. `pasivo/fingerprinting-tecnologias-web.md` y `web/fingerprinting-tecnologias-web.md`). Resolución: añadir modificador al nombre del archivo (`fingerprinting-tecnologias-web-activo.md`). El validador detecta colisiones de slug y obliga a fixar.

### Variantes válidas

- **Compound `fase`** (técnica/herramienta que cruza fases genuinamente, ej. BloodHound, Metasploit): listar varios valores en el array. Ejemplo: `fase: [Reconocimiento, Post-Explotación]`.
- **Contenido conceptual o metodológico** (modelos teóricos como OSI, ciclos como PICERL, marcos como NIST CSF): las secciones Herramientas, Comandos / Ejemplos y Contramedidas son **opcionales**. Pueden sustituirse por secciones propias relevantes al tema. El frontmatter sigue siendo obligatorio. Las secciones de body obligatorias en este perfil son sólo: Título, Descripción, Referencias.
- **`plataforma`** se mantiene siempre estricta (un valor de la lista). Sin paréntesis explicativos. El contexto cross-plataforma (ej. "tool corre en Linux pero target es Windows") va en Descripción.

### Formato de Referencias (APA 7ma Edición)

Todas las referencias deben seguir el estilo APA. Ejemplos por tipo de fuente:

**Libros de `referencias/`:**
```
Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
Kennedy, D., O'Gorman, J., Kearns, D., & Aharoni, M. (2011). *Metasploit: The Penetration Tester's Guide*. No Starch Press.
```

**Frameworks y bases de datos online:**
```
MITRE Corporation. (2024). ATT&CK Technique T1595: Active Scanning. https://attack.mitre.org/techniques/T1595/
OWASP Foundation. (2021). *OWASP Top Ten*. https://owasp.org/www-project-top-ten/
```

**Herramientas y repositorios:**
```
EnableSecurity. (s.f.). *wafw00f* [Software]. GitHub. https://github.com/EnableSecurity/wafw00f
swisskyrepo. (s.f.). *PayloadsAllTheThings* [Repositorio]. GitHub. https://github.com/swisskyrepo/PayloadsAllTheThings
```

> **Nota**: Para libros de `referencias/`, usar los datos reales del PDF (autor, año, editorial). Usar `(s.f.)` (sin fecha) cuando no se conozca el año de publicación.

## Convención de Naming de Archivos

Los archivos del inventario siguen un patrón `<prefijo-acción>-<slug-del-tema>.md` en kebab-case. La uniformidad permite a un agente predecir el nombre de un archivo sin consultar el INDEX.

### Reglas

1. **Prefijo de acción** según fase del archivo:
   - `analisis-` para Fase 03 (Análisis de Vulnerabilidades).
   - `explotacion-` para Fase 04 (Explotación).
   - `enumeracion-` para Fase 02 (Enumeración).
   - `abuso-` en Fase 05 cuando la técnica explota una feature legítima del SO (sudo, cron, services, scheduled tasks).
   - Sin prefijo en Fase 05 cuando el nombre de la técnica ES el slug (`pass-the-hash`, `suid-sgid`, `pivoting-tunneling`).
   - Para herramientas/frameworks (Fase 06) y conceptos (Fase 07-08) no se aplica prefijo de acción; usar el nombre directo (`bloodhound.md`, `modelo-osi-tcp-ip.md`).

2. **Slug del tema** en kebab-case. Cuando exista un acrónimo establecido en el dominio, **usarlo en lugar de la palabra completa**:
   - SQL Injection → `sqli` (no `sql-injection`).
   - Cross-Site Scripting → `xss`.
   - Cross-Site Request Forgery → `csrf`.
   - Server-Side Request Forgery → `ssrf`.
   - Insecure Direct Object Reference → `idor`.
   - Local/Remote File Inclusion → `lfi-rfi`.
   - XML External Entity → `xxe`.
   - Server-Side Template Injection → `ssti`.
   - JSON Web Token → `jwt`.
   - NoSQL Injection → `nosqli`.
   - Active Directory Certificate Services → `adcs`.

3. **Pares cross-fase deben coincidir** en el slug del tema: `analisis-sqli.md` ↔ `explotacion-sqli.md`. Esto permite al agente buscar todas las técnicas relacionadas a un tópico con `find inventario -name "*-<slug>.md"`.

4. **Slug compuesto cuando aplique**: usar `-` para separar modificadores. Ejemplos: `enumeracion-privesc-linux.md`, `abuso-tareas-programadas.md`, `kernel-exploits-privesc-linux.md`.

## Cookbook de Búsqueda (para agentes/LLM)

Patrones de grep frecuentes sobre el inventario. La metadata vive en frontmatter YAML al inicio de cada archivo técnico, así que las queries más útiles son sobre líneas con `^<campo>:`. La fase 01 ya está migrada; las fases 02-08 se migran progresivamente.

```bash
# Localizar un archivo por slug exacto:
grep -lE "^slug: analisis-sqli$" inventario/**/*.md

# Localizar todos los archivos de un tópico cruzando fases (recomendado):
find inventario -name "*-sqli.md"                       # captura analisis-sqli, explotacion-sqli, etc.
grep -rlE "^slug: .*[-_]sqli($|[-.])" inventario/      # equivalente vía slug, captura sufijos
grep -rl "^aliases:.*\bSQLi\b" inventario/             # por alias declarado

# Listar todos los slugs únicos del inventario:
grep -hE "^slug: " inventario/**/*.md | sort -u

# Filtrar por dificultad:
grep -lE "^dificultad: Avanzada$" inventario/**/*.md

# Filtrar por plataforma:
grep -lE "^plataforma: Web$" inventario/**/*.md

# Filtrar por MITRE técnica (incluye sub-técnica):
grep -lE "^mitre:.*\bT1190\b" inventario/**/*.md

# Filtrar por fase (string exacto entre brackets/comas):
grep -lE "^fase:.*Post-Explotación" inventario/**/*.md

# Búsqueda por alias (técnica conocida en otro idioma o por acrónimo):
grep -lE "^aliases:.*Inyección SQL" inventario/**/*.md

# Listar archivos que tienen learning_refs (writeups asociados):
grep -lE "^learning_refs: \[[^]]" inventario/**/*.md

# Combinaciones (intersect): técnicas Avanzadas en plataforma Web
grep -lE "^dificultad: Avanzada$" inventario/**/*.md | xargs grep -lE "^plataforma: Web$"

# Listar herramientas que aparecen en sección Herramientas (texto del body):
grep -hE "^- \*\*[A-Z]" inventario/**/*.md | sort -u

# Encontrar archivos que mencionan una herramienta específica en el body:
grep -l "BloodHound" inventario/**/*.md
grep -l "sqlmap" inventario/**/*.md

# Encontrar archivos que referencian un libro por autor (en sección Referencias):
grep -l "Allen, L." inventario/**/*.md
```

> **Nota legacy**: para archivos aún no migrados (fases 02-08 mientras dura Sprint 1), la metadata vive como `**Fase**: ...` en el body. Si un grep sobre frontmatter devuelve menos resultados de los esperados, complementar con queries legacy: `grep -lE "Dificultad.*Avanzada"`, `grep -lE "Plataforma.*Web"`, etc.

## Política `learning_refs` (writeups linkeables)

`learning/` contiene material práctico de cursos (PortSwigger, TryHackMe). Sólo es candidato a referenciarse desde el inventario el material que sea un **writeup estructurado**, no scratch ni código suelto.

**Es linkeable** un directorio que cumple ambas condiciones:
1. Vive en `learning/<plataforma>/<lab-slug>/`.
2. Contiene un archivo `writeup.md` (o equivalente Markdown estructurado) con descripción del problema, solución y referencias.

**No son linkeables**: directorios con sólo scripts (`.py`, `.sh`, `.rb`), wordlists, archivos sueltos al nivel raíz de `learning/<plataforma>/`, ni material de curso fragmentado sin un writeup consolidado.

Cuando se añada `learning_refs:` a archivos del inventario (Sprint 1 del plan de discoverabilidad), sólo apuntar a directorios de la lista linkeable.

## Heurísticas de Prioridad

Para garantizar la precisión y actualidad del inventario, los agentes deben seguir este orden de prioridad al recopilar información:

1. **Prioridad 1: Autoridad Oficial (Internet)**: MITRE ATT&CK, OWASP, CVE, documentación oficial. Es la fuente de verdad para definiciones, taxonomía y mitigaciones.
2. **Prioridad 2: Profundidad Técnica (Libros `referencias/`)**: Proporcionan el contexto técnico detallado y fundamentos sólidos.
3. **Prioridad 3: Notas vivas del proyecto** (si existen): Si hay un dir de writeups complementarios externos al inventario (ej. `learning/` u otros repos del usuario referenciados explícitamente), consultarlo para ejemplos prácticos. Si no, depender exclusivamente de Prioridad 1 y 2.

### Resolución de Conflictos
- **Teoría/Definiciones**: Si hay discrepancia, manda la fuente Oficial.
- **Comandos/Práctica**: Si una nota personal tiene un comando probado que difiere de un libro, se incluyen ambos o se prioriza el que sea funcionalmente más reciente/efectivo.
- **Duplicados en el inventario**: Si existen múltiples archivos cubriendo la misma técnica, consolidar en uno (mayor riqueza de contenido + fecha más reciente prevalecen) y eliminar el otro. Actualizar el INDEX.md correspondiente.

## Agentes

### `investigador`
- **Rol**: Extrae técnicas de las fuentes existentes (`inventario/`, `referencias/`, internet)
- **Input**: Un tema o fase del inventario
- **Output**: Lista de técnicas encontradas con nombre, descripción, comandos y ruta del archivo fuente
- **Herramientas**: Read, Grep, Glob, WebSearch, WebFetch
- **Instrucciones**:
  1. Explorar el propio `inventario/` (Glob y Grep) para detectar coverage existente del tema antes de añadir contenido nuevo
  2. Si hay coverage existente, evaluar si actualizar o si el tema requiere un archivo nuevo
  3. Para temas no cubiertos, consultar `referencias/` (vía RAG) y fuentes web según `Heurísticas de Prioridad`
  4. Agrupar herramientas individuales en técnicas lógicas cuando sirven al mismo propósito
  5. Si el tema tiene subtemas independientes, se pueden lanzar múltiples instancias en paralelo

### `redactor`
- **Rol**: Escribe y estructura cada técnica siguiendo el formato estándar
- **Input**: Información en bruto sobre una técnica (del `investigador`)
- **Output**: Archivo Markdown formateado y guardado en la ruta correcta del inventario
- **Herramientas**: Read, Write, Edit
- **Instrucciones**:
  1. Aplicar el formato de TEMPLATE.md según el perfil del contenido: técnicas concretas usan las 7 secciones (Título + 6 H2); contenido conceptual/metodológico puede omitir Herramientas, Comandos / Ejemplos y Contramedidas y sustituirlas por secciones propias relevantes
  2. Verificar el ID de MITRE ATT&CK antes de incluirlo — usar el sub-técnica correcto, no sólo el padre. Para CSRF/IDOR/race conditions y similares vulnerabilidades de aplicación sin mapping limpio, usar T1190 por defecto
  3. Incluir referencias a libros de `referencias/` cuando sean relevantes
  4. Usar formato APA 7ma edición para todas las referencias (ver guía de formato arriba)
  5. Se pueden lanzar múltiples instancias en paralelo cuando hay subtemas independientes

### `revisor`
- **Rol**: Valida la calidad, completitud y precisión técnica del inventario
- **Input**: Archivos del inventario generados (por fase o directorio)
- **Output**: Reporte con issues por archivo y resumen de problemas transversales
- **Herramientas**: Read, Glob, Grep
- **Instrucciones**: Verificar en cada archivo:
  1. **Frontmatter YAML presente y correcto** al inicio del archivo (entre `---` ... `---`):
     - Campos requeridos: `title`, `slug`, `aliases`, `fase`, `plataforma`, `dificultad`, `mitre`. Opcionales: `related`, `learning_refs`.
     - `slug` único en el inventario, kebab-case, usa acrónimo establecido (sqli/xss/csrf/etc.) cuando aplique.
     - `fase` y `mitre` son arrays incluso con un único valor.
     - Enums respetados: `plataforma ∈ {Linux, Windows, Web, Red, Multi}`, `dificultad ∈ {Básica, Intermedia, Avanzada}`, `fase ∈` las 7 fases permitidas.
     - `mitre` con formato `T\d{4}(\.\d{3})?`.
     - `title` coincide con el H1 del body.
  2. Las secciones de body obligatorias están presentes según perfil del contenido:
     - Técnicas/herramientas concretas: 5 secciones (Descripción, Herramientas, Comandos / Ejemplos, Contramedidas, Referencias) más el H1 y el frontmatter.
     - Contenido conceptual/metodológico (07-fundamentos, 08-forense-dfir/incident-response, modelos teóricos): 2 secciones obligatorias (Descripción, Referencias) más el H1, el frontmatter, y las secciones propias relevantes.
     - **Ningún archivo debe tener una sección `## Clasificación`** (deprecada en favor del frontmatter).
  3. El ID de MITRE ATT&CK es correcto y la sub-técnica aplica. T1190 es el ID por defecto defensible para vulnerabilidades de aplicación sin mapping limpio (CSRF, IDOR, race conditions).
  4. El archivo está en la carpeta correcta según la taxonomía y el nombre sigue la convención de naming (prefijo de acción + slug acrónimo).
  5. Los comandos son sintácticamente correctos y no usan herramientas desactualizadas.
  6. Las referencias siguen formato APA y al menos una corresponde a un libro de `referencias/`.
  7. Acentos y ortografía españolas correctas en todo el cuerpo del archivo.

## Workflow Probado

El siguiente flujo fue validado al construir `01-reconocimiento/`. Usarlo como base para las fases siguientes.

### Paso 1 — Investigacion
Lanzar uno o mas agentes `investigador` según la complejidad de la fase. Si hay subtemas claramente independientes (ej: distintas carpetas dentro de la fase), lanzarlos en paralelo para acelerar. Cada agente consulta el `inventario/` actual, las fuentes en `referencias/` (vía RAG) y la web según prioridad, devolviendo lista de técnicas con comandos y rutas fuente.

### Paso 2 — Redaccion
Con la información del paso anterior, lanzar agentes `redactor`. Se pueden lanzar en paralelo por subtema. Los agentes crean los archivos directamente en `inventario/0X-fase/`.

### Paso 3 — Review
Lanzar un agente `revisor` sobre todos los archivos creados en la fase. El revisor lee cada archivo completo y genera un reporte estructurado con issues por archivo y problemas transversales.

### Paso 4 — Correccion
Aplicar las correcciones del reporte. Issues recurrentes encontrados en Fase 01 (a vigilar en fases futuras):
- **MITRE IDs incorrectos**: Verificar siempre el sub-técnica, no solo el padre
- **Archivo en carpeta incorrecta**: Evaluar si la técnica es realmente del subtema asignado
- **Herramientas desactualizadas**: Verificar si la herramienta sigue mantenida activamente
- **Plataforma demasiado restrictiva**: Técnicas de red/sistema suelen ser "Multi", no "Web"
- **Falta de referencias a libros**: Todos los archivos deben citar al menos un libro de `referencias/`

### Paso 5 — Actualizacion del CHANGELOG
Registrar en `CHANGELOG.md` bajo la fecha actual:
- Técnicas añadidas (lista con nombres de archivo)
- Correcciones aplicadas
- Cambios a `AGENTS.md` o formato

## Configuración RAG

Configuración para el motor de búsqueda semántica local sobre los libros de `referencias/`.

| Parámetro | Valor |
|-----------|-------|
| `--source-dir` | `/home/sebastian/Documentos/inventario-técnicas-ciberseguridad/referencias/` |
| `--db-path` | `/home/sebastian/Documentos/rag/chroma_db/` |
| `--collection-name` | `ciberseguridad-referencias` |
| `--n-results` | `5` |

