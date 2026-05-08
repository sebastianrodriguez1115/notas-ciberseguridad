---
title: Broken Access Control
slug: explotacion-broken-access-control
aliases: [BAC, broken access control, access control bypass, authorization bypass, missing function level access control, vertical privilege escalation, horizontal privilege escalation, forced browsing, unprotected admin, security through obscurity, role-based bypass, privilege escalation web, OWASP A01, mass assignment, sobre-aceptacion de campos, BOPLA, broken object property level authorization, autobinding vulnerability, strong parameters bypass, URL-based access control bypass, X-Original-URL bypass, X-Rewrite-URL bypass, header rewrite bypass, frontend backend split-brain, header smuggling routing, X-Forwarded-Path]
fase: [Explotación]
plataforma: Web
dificultad: Básica
mitre: [T1190]
related: [analisis-idor, explotacion-mfa-bypass, explotacion-jwt]
learning_refs: [portswigger/unprotected-admin-functionality, portswigger/unprotected-admin-functionality-with-unpredictable-url, portswigger/user-role-controlled-by-request-parameter, portswigger/user-role-can-be-modified-in-user-profile, portswigger/url-based-access-control-can-be-circumvented]
---

# Broken Access Control

## Descripción
Conjunto de vulnerabilidades en las que el server falla en validar que el usuario que hace una request tenga el permiso necesario para esa acción. Top 1 del OWASP Top 10 desde 2021. Incluye paneles admin sin auth, endpoints que confían en parámetros del cliente para identidad, métodos HTTP no chequeados, multi-step flows que se pueden saltear, escalada vertical (user → admin) u horizontal (user A → user B). El defender frecuentemente se apoya en obscuridad (URL no linkeada), UI hiding (botones admin escondidos en el frontend), o asunciones tácitas ("este endpoint solo lo llama el admin panel"). Ninguna de esas es defensa real: el atacante construye la request directamente, ignorando UI y descubriendo paths por wordlists, JS leaks, robots.txt, o stack traces.

## Categorías

- **Functional level access control missing**: el endpoint sensible no exige auth/role. Atacante anónimo o usuario común accede al feature admin (panel de delete users, export DB, run jobs). Caso del lab `unprotected-admin-functionality`.
- **IDOR (Insecure Direct Object Reference)**: el endpoint requiere auth pero usa identifier del cliente (`?account_id=42`) sin chequear ownership. User A accede a recursos de User B cambiando el ID. Cubierto en `analisis-idor.md`.
- **Method-based bypass**: protección solo en GET, no en POST (o viceversa). Cambiar método para saltearse el check.
- **URL-based bypass**: middleware chequea por path string match (`/admin*`); bypass con `/admin/`, `/Admin`, `/admin..;/`, normalización inconsistente.
- **Multi-step process bypass**: flujo de 3 pasos donde el paso 2 valida la transición pero el paso 3 se puede invocar directamente.
- **Referer-based access control**: server confía en `Referer:` header para decidir si es request "interna". Atacante manda Referer falsificado.
- **Vertical privilege escalation**: user → admin. Cambiar rol en JWT, manipular cookie de role, exploit de mass assignment.
- **Horizontal privilege escalation**: user A → user B (mismo nivel). Típicamente IDOR.

## Herramientas
- **Burp Suite (Repeater + Intruder)**: manipular auth headers, IDs, métodos HTTP. Match-replace para escalar role.
- **Burp Suite (Authorize plugin)**: testing automatizado de access control comparando respuestas con/sin auth.
- **ffuf / gobuster / feroxbuster**: forced browsing para descubrir endpoints sensibles.
- **curl**: scripting rápido de requests anónimas o con credenciales rotadas.
- **JWT.io / jwt-tool**: inspección y forge de JWTs para escalar privilegios.

## Comandos / Ejemplos

### Descubrir endpoints sensibles
```bash
# robots.txt: lista de objetivos potenciales
curl -s https://target/robots.txt

# Forced browsing con wordlist común
ffuf -u https://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -mc 200,301,302,403

# Buscar paths admin específicos
ffuf -u https://target/FUZZ -w /usr/share/seclists/Discovery/Web-Content/AdminPanels.txt
```

### Bypass functional-level (panel admin sin auth)
```bash
# Acceso directo, sin cookie
curl https://target/administrator-panel
# Si responde 200 con contenido sensible, vuln confirmada

# Ejecutar acción admin
curl 'https://target/administrator-panel/delete?username=victim'
```

### Escalada por header
```bash
# Probar si el server confía en headers de proxy para identity
curl https://target/admin -H 'X-Forwarded-For: 127.0.0.1'
curl https://target/admin -H 'X-Original-URL: /admin'
curl https://target/admin -H 'X-Rewrite-URL: /admin'
```

### Method bypass
```bash
# Si GET /admin/delete está protegido, probar POST
curl -X POST https://target/admin/delete -d 'username=victim'

# Ver allow methods
curl -X OPTIONS https://target/admin -i
```

## Contramedidas
- **Deny by default**: cada endpoint declara explícitamente sus requisitos. Sin decorator/middleware → falla cerrado.
- **Decorators o middleware consistentes**: `@require_role('admin')`, evita olvidos por endpoint.
- **Authorization en server-side, no en frontend**: ocultar botones es UX, no seguridad.
- **No confiar en parámetros del cliente para identidad**: el `user_id` del recurso siempre se compara con la sesión, no con un input.
- **Distinguir 401 vs 403**: no autenticado vs autenticado-sin-permisos. Mejora detección y UX.
- **POST/DELETE para mutaciones, con CSRF token**: GET es idempotente y vulnerable a CSRF.
- **Audit logging**: registrar acciones sensibles (quién, qué, cuándo, target) para forensics.
- **Threat modeling**: enumerar todos los endpoints sensibles y verificar cada uno tenga authz check.
- **Tests automatizados de access control**: por cada endpoint sensible, test que verifica 401 sin auth y 403 con auth-pero-no-permisos.

## Referencias
- OWASP Foundation. (2021). *A01:2021 - Broken Access Control*. https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- OWASP Foundation. (s.f.). *Authorization Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- OWASP Foundation. (s.f.). *Access Control Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html
- PortSwigger Web Security Academy. (s.f.). *Access control vulnerabilities and privilege escalation*. https://portswigger.net/web-security/access-control
- MITRE Corporation. (2024). *CWE-284: Improper Access Control*. https://cwe.mitre.org/data/definitions/284.html
- MITRE Corporation. (2024). *CWE-285: Improper Authorization*. https://cwe.mitre.org/data/definitions/285.html
- MITRE Corporation. (2024). *CWE-862: Missing Authorization*. https://cwe.mitre.org/data/definitions/862.html
- MITRE Corporation. (2024). *CWE-863: Incorrect Authorization*. https://cwe.mitre.org/data/definitions/863.html
- MITRE Corporation. (2024). *ATT&CK Technique T1190: Exploit Public-Facing Application*. https://attack.mitre.org/techniques/T1190/
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook* (2nd ed.). Wiley. Cap. 8 (Attacking Access Controls).
- Hoffman, A. (2020). *Web Application Security*. O'Reilly. Cap. 16 (Authorization).
