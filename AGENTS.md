# Inventario de Tecnicas de Ciberseguridad - AGENTS.md

## Objetivo

Construir un inventario estructurado y completo de tecnicas de ciberseguridad, organizado por fases del ciclo de penetration testing, cubriendo desde reconocimiento hasta post-explotacion.

## Fuentes de Informacion

### 1. `notas-md/` — Notas personales (Notion export convertido a Markdown)

Contiene **222 archivos Markdown** + 108 imagenes organizados en:

#### INE Courses (~58 archivos)
Cursos estructurados de INE cubriendo:
- **Assessment Methodologies**: Footprinting, Scanning, Information Gathering (pasivo/activo), Enumeration por protocolo (HTTP, SSH, FTP, SMB, MySQL, MSSQL)
- **Host & Network Penetration Testing**: Explotacion de vulnerabilidades Windows (EternalBlue, RDP, SMB, WebDAV, WinRM) y Linux (Shellshock), SNMP Enumeration
- **Metasploit Framework**: Information Gathering, Vulnerability Scanning, Client-Side Attacks (msfvenom payloads, encoding, PE injection), Automating (resource scripts)
- **Exploitation**: Searchsploit, Banner Grabbing, Netcat, PowerShell-Empire
- **Network Based Attacks**: MITM
- **Privilege Escalation**: Windows y Linux

#### HNotes (~164 archivos)
Notas propias organizadas por tecnica/herramienta:
- **Recon** (~44 archivos): Passive (Shodan, Censys, Wappalyzer, Wayback, Certificate Fingerprinting) y Active (nmap, dnsrecon, subfinder, amass, gobuster, httpx, arp-scan), Fuzzing (ffuf), OSINT
- **Hacking** (~29 archivos): Brute Force (Hydra), SQLi (SQLMap), XSS, File Inclusion, Hash Cracking (Hashcat, Crackstation, CyberChef), Privilege Escalation (linPEAS, winPEAS), Ransomware
- **Burp Suite Labs** (~49 archivos): CORS, CSRF, SQL Injection, XSS — writeups de laboratorios practicos
- **General** (~22 archivos): Cryptography, Active Directory, Linux/Windows commands, OSI Model, JWT, CVSS, GRC Frameworks, Yara Rules, Bash/Python scripting
- **TryHackMe** (~20 archivos): CTF writeups (Lateral Movement, DOM-Based Attacks, WAF Bypass, HTTP/2 Tunneling, Data Exfiltration)

### 2. `referencias/` — Libros de referencia (33 PDFs)

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
| Web Penetration Testing with Kali Linux | Pentesting Web |

### 3. Internet — Frameworks, Bases de Conocimiento y Recursos Abiertos

#### Frameworks y Taxonomias de Ataques

| Recurso | URL | Descripcion |
|---------|-----|-------------|
| **MITRE ATT&CK** | https://attack.mitre.org/ | Base de conocimiento de tacticas y tecnicas adversarias basada en observaciones reales. Estructura matriz por fases (Initial Access → Impact). Referencia principal para mapear tecnicas. |
| **MITRE ATLAS** | https://atlas.mitre.org/ | Extension de ATT&CK para ataques contra sistemas de IA/ML. |
| **CAPEC** | https://capec.mitre.org/ | Common Attack Pattern Enumeration and Classification. Catalogo de patrones de ataque con enfoque en aplicaciones. Complementa ATT&CK a nivel de implementacion. |
| **CWE** | https://cwe.mitre.org/ | Common Weakness Enumeration. Lista de debilidades de software/hardware que pueden ser explotadas. |
| **Cyber Kill Chain** | https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html | Modelo lineal de 7 fases de un ciberataque (Lockheed Martin). |

#### Estandares de Seguridad Web

| Recurso | URL | Descripcion |
|---------|-----|-------------|
| **OWASP Top 10** | https://owasp.org/www-project-top-ten/ | Las 10 vulnerabilidades web mas criticas. Referencia fundamental para seguridad de aplicaciones. |
| **OWASP Web Security Testing Guide (WSTG)** | https://owasp.org/www-project-web-security-testing-guide/ | Guia completa de testing de seguridad web con metodologia paso a paso. |
| **OWASP API Security Top 10** | https://owasp.org/API-Security/ | Top 10 riesgos de seguridad en APIs. |
| **OWASP Mobile Top 10** | https://owasp.org/www-project-mobile-top-10/ | Top 10 riesgos de seguridad en aplicaciones moviles. |
| **OWASP Cheat Sheet Series** | https://cheatsheetseries.owasp.org/ | Cheat sheets de contramedidas para desarrolladores. |

#### Bases de Datos de Vulnerabilidades y Exploits

| Recurso | URL | Descripcion |
|---------|-----|-------------|
| **NVD (National Vulnerability Database)** | https://nvd.nist.gov/ | Repositorio gubernamental de EE.UU. con datos de vulnerabilidades (SCAP). Incluye scoring CVSS. |
| **CVE Program** | https://www.cve.org/ | Identificadores estandar para vulnerabilidades conocidas. |
| **CVE Details** | https://www.cvedetails.com/ | Agregador de CVEs con busqueda avanzada, estadisticas y feeds. |
| **Exploit-DB** | https://www.exploit-db.com/ | Base de datos de exploits, shellcode y papers de seguridad. Mantenida por OffSec. |
| **CISA KEV** | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | Catalogo de vulnerabilidades activamente explotadas (Known Exploited Vulnerabilities). |

#### Knowledge Bases y Cheatsheets Ofensivos

| Recurso | URL | Descripcion |
|---------|-----|-------------|
| **HackTricks** | https://hacktricks.wiki/ | Wiki extensiva de tecnicas de hacking, CTFs, privilege escalation, AD attacks. Recurso central para pentesting. |
| **PayloadsAllTheThings** | https://github.com/swisskyrepo/PayloadsAllTheThings | Repositorio de payloads y bypasses para seguridad web y pentesting. Organizado por tipo de vulnerabilidad. |
| **GTFOBins** | https://gtfobins.github.io/ | Binarios Unix que permiten bypass de restricciones locales (sudo, SUID, capabilities). Esencial para privesc Linux. |
| **LOLBAS** | https://lolbas-project.github.io/ | Living Off The Land Binaries, Scripts and Libraries para Windows. Equivalente de GTFOBins para Windows. |
| **LOLAD** | https://lolad-project.github.io/ | Living Off The Land in Active Directory. Tecnicas de explotacion de AD con herramientas nativas. |
| **RevShells** | https://www.revshells.com/ | Generador de reverse shells en multiples lenguajes. |
| **CyberChef** | https://gchq.github.io/CyberChef/ | Herramienta web para encoding/decoding, crypto, analisis de datos. |

#### Metodologias de Pentesting

| Recurso | URL | Descripcion |
|---------|-----|-------------|
| **PTES** | http://www.pentest-standard.org/ | Penetration Testing Execution Standard. Define el ciclo completo de un pentest. |
| **OSSTMM** | https://www.isecom.org/OSSTMM.3.pdf | Open Source Security Testing Methodology Manual. Metodologia peer-reviewed para security testing. |
| **NIST SP 800-115** | https://csrc.nist.gov/publications/detail/sp/800-115/final | Guia tecnica de NIST para pruebas de seguridad. Estandar para entornos regulados. |

#### Compliance y Defensive Frameworks

| Recurso | URL | Descripcion |
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
├── 02-enumeracion/
│   ├── web/                 # HTTP, directorios, tecnologias, CMS
│   ├── red/                 # SMB, SNMP, NFS, DNS
│   ├── servicios/           # SSH, FTP, MySQL, MSSQL, RDP, WinRM
│   └── fuzzing/             # ffuf, gobuster, wordlists
├── 03-analisis-vulnerabilidades/
│   ├── scanning/            # Nessus, OpenVAS, nmap scripts
│   ├── web/                 # SQLi, XSS, CSRF, CORS, SSRF, File Inclusion
│   └── sistema/             # CVEs conocidos, misconfigurations
├── 04-explotacion/
│   ├── web/                 # inyecciones, auth bypass, deserialization
│   ├── red/                 # MITM, relay attacks, protocol abuse
│   ├── sistema/             # buffer overflow, kernel exploits, shellshock, eternalblue
│   ├── client-side/         # payloads, msfvenom, PE injection, phishing
│   └── credenciales/        # brute force, hash cracking, password spraying
├── 05-post-explotacion/
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
│   ├── criptografia/        # hashing, encryption, PKI, JWT
│   ├── redes/               # OSI, TCP/IP, subnetting, firewalls
│   ├── sistemas/            # Linux commands, Windows commands, AD
│   └── compliance/          # CVSS, GRC frameworks
└── 08-forense-dfir/
    ├── analisis-forense/    # disk, memory, mobile, network forensics
    ├── incident-response/   # containment, eradication, recovery
    └── malware-analysis/    # static, dynamic, yara rules
```

## Idioma y Ortografía

Todo el contenido del inventario debe estar escrito en español con ortografía correcta, incluyendo acentos (á, é, í, ó, ú), eñes (ñ) y signos de puntuación invertidos (¿, ¡) donde corresponda. Ejemplos: "Descripción", "Clasificación", "Técnica", "contraseña", "enumeración", "gestión", "configuración", "básica", etc.

## Formato de cada Tecnica

Cada tecnica del inventario se documenta como un archivo Markdown siguiendo el template de referencia en **`inventario/TEMPLATE.md`**. Ese archivo contiene la estructura exacta, ejemplos de formato para cada campo y notas detalladas para el redactor en un bloque de comentario HTML al final. **Antes de crear o editar cualquier archivo del inventario, leer el template completo.**

La estructura resumida es:

```markdown
# Nombre de la Tecnica

## Descripcion
Que es y para que se usa.

## Clasificacion
- **Fase**: Reconocimiento | Enumeracion | Explotacion | Post-Explotacion | ...
- **MITRE ATT&CK**: ID de la tecnica si aplica (ej. T1595)
- **Plataforma**: Linux | Windows | Web | Red | Multi
- **Dificultad**: Basica | Intermedia | Avanzada

## Herramientas
- Herramienta 1 — uso basico
- Herramienta 2 — uso basico

## Comandos / Ejemplos
Ejemplos practicos con comandos reales.

## Contramedidas
Como defenderse de esta tecnica.

## Referencias
- Referencias en formato APA 7ma edicion (ver guia de formato abajo).
```

### Formato de Referencias (APA 7ma Edicion)

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

**Notas personales del proyecto:**
```
Notas del proyecto: notas-md/HNotes/Recon/Active Enumeration/nmap.md
Notas del proyecto: notas-md/INE Courses/Assessment Methodologies Enumeration/SMB/nmap scripts.md
```

> **Nota**: Para libros de `referencias/`, usar los datos reales del PDF (autor, año, editorial). Usar `(s.f.)` (sin fecha) cuando no se conozca el año de publicacion.

## Heurísticas de Prioridad

Para garantizar la precisión y actualidad del inventario, los agentes deben seguir este orden de prioridad al recopilar información:

1. **Prioridad 1: Autoridad Oficial (Internet)**: MITRE ATT&CK, OWASP, CVE, documentación oficial. Es la fuente de verdad para definiciones, taxonomía y mitigaciones.
2. **Prioridad 2: Profundidad Técnica (Libros `referencias/`)**: Proporcionan el contexto técnico detallado y fundamentos sólidos.
3. **Prioridad 3: Contexto Práctico (Notas `notas-md/`)**: Fuente primordial para ejemplos de comandos reales, "tricks" de laboratorios y flujos de trabajo probados.

### Resolución de Conflictos
- **Teoría/Definiciones**: Si hay discrepancia, manda la fuente Oficial.
- **Comandos/Práctica**: Si una nota personal tiene un comando probado que difiere de un libro, se incluyen ambos o se prioriza el que sea funcionalmente más reciente/efectivo.
- **Duplicados Locales**: En caso de múltiples versiones de una misma nota en `notas/`, se prioriza la versión con mayor riqueza de contenido (tamaño) y fecha de modificación más reciente.

## Agentes

### `investigador`
- **Rol**: Extrae tecnicas de las fuentes existentes (notas-md/, referencias/, internet)
- **Input**: Un tema o fase del inventario
- **Output**: Lista de tecnicas encontradas con nombre, descripcion, comandos y ruta del archivo fuente
- **Herramientas**: Read, Grep, Glob, WebSearch, WebFetch
- **Instrucciones**:
  1. Explorar `notas-md/` buscando archivos relacionados con el tema (Glob y Grep)
  2. Leer el contenido de cada archivo relevante para extraer detalles
  3. Agrupar herramientas individuales en tecnicas logicas cuando sirven al mismo proposito
  4. Si el tema tiene subtemas independientes, se pueden lanzar multiples instancias en paralelo

### `redactor`
- **Rol**: Escribe y estructura cada tecnica siguiendo el formato estandar
- **Input**: Informacion en bruto sobre una tecnica (del `investigador`)
- **Output**: Archivo Markdown formateado y guardado en la ruta correcta del inventario
- **Herramientas**: Read, Write, Edit
- **Instrucciones**:
  1. Aplicar el formato de 7 secciones definido en este archivo
  2. Verificar el ID de MITRE ATT&CK antes de incluirlo — usar el sub-tecnica correcto, no solo el padre
  3. Incluir referencias a libros de `referencias/` cuando sean relevantes
  4. Usar formato APA 7ma edicion para todas las referencias (ver guia de formato arriba)
  5. Se pueden lanzar multiples instancias en paralelo cuando hay subtemas independientes

### `revisor`
- **Rol**: Valida la calidad, completitud y precision tecnica del inventario
- **Input**: Archivos del inventario generados (por fase o directorio)
- **Output**: Reporte con issues por archivo y resumen de problemas transversales
- **Herramientas**: Read, Glob, Grep
- **Instrucciones**: Verificar en cada archivo:
  1. Las 7 secciones del formato estan presentes
  2. El ID de MITRE ATT&CK es correcto y el sub-tecnica aplica
  3. El archivo esta en la carpeta correcta segun la taxonomia
  4. Los comandos son sintacticamente correctos y no usan herramientas desactualizadas
  5. Las referencias siguen formato APA y los libros citados existen en `referencias/`
  6. El campo `Plataforma` es consistente con el contenido

## Workflow Probado

El siguiente flujo fue validado al construir `01-reconocimiento/`. Usarlo como base para las fases siguientes.

### Paso 1 — Investigacion
Lanzar uno o mas agentes `investigador` segun la complejidad de la fase. Si hay subtemas claramente independientes (ej: distintas carpetas dentro de la fase), lanzarlos en paralelo para acelerar. Cada agente lee todos los archivos relevantes en `notas-md/` y devuelve lista de tecnicas con comandos y rutas fuente.

### Paso 2 — Redaccion
Con la informacion del paso anterior, lanzar agentes `redactor`. Se pueden lanzar en paralelo por subtema. Los agentes crean los archivos directamente en `inventario/0X-fase/`.

### Paso 3 — Review
Lanzar un agente `revisor` sobre todos los archivos creados en la fase. El revisor lee cada archivo completo y genera un reporte estructurado con issues por archivo y problemas transversales.

### Paso 4 — Correccion
Aplicar las correcciones del reporte. Issues recurrentes encontrados en Fase 01 (a vigilar en fases futuras):
- **MITRE IDs incorrectos**: Verificar siempre el sub-tecnica, no solo el padre
- **Archivo en carpeta incorrecta**: Evaluar si la tecnica es realmente del subtema asignado
- **Herramientas desactualizadas**: Verificar si la herramienta sigue mantenida activamente
- **Plataforma demasiado restrictiva**: Tecnicas de red/sistema suelen ser "Multi", no "Web"
- **Falta de referencias a libros**: Todos los archivos deben citar al menos un libro de `referencias/`

### Paso 5 — Actualizacion del CHANGELOG
Registrar en `CHANGELOG.md` bajo la fecha actual:
- Tecnicas añadidas (lista con nombres de archivo)
- Correcciones aplicadas
- Cambios a `AGENTS.md` o formato

