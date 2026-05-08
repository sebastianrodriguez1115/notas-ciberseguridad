---
title: "Explotación: Insecure Direct Object Reference (IDOR)"
slug: explotacion-idor
aliases: [IDOR, Insecure Direct Object Reference, BOLA, Broken Object Level Authorization, horizontal privilege escalation, object-level authz bypass, parameter tampering ID, predictable IDs, sequential IDs leak, GUID leak, UUID leak, unpredictable IDs no son authz, random IDs no son control acceso, data leakage in redirect, redirect cosmetico no es authz, body leak en 302, render antes de check, status code no es access control]
fase: [Explotación]
plataforma: Web
dificultad: Básica
mitre: [T1190]
related: [analisis-idor, explotacion-broken-access-control]
learning_refs: [portswigger/user-id-controlled-by-request-parameter, portswigger/user-id-controlled-by-request-parameter-with-unpredictable-user-ids, portswigger/user-id-controlled-by-request-parameter-with-data-leakage-in-redirect]
---

# Explotación: Insecure Direct Object Reference (IDOR)

## Descripción
Explotación de vulnerabilidades donde el server expone identificadores de objeto (IDs, usernames, slugs, UUIDs) en URLs/parámetros y los usa para devolver el recurso correspondiente sin chequear que el usuario autenticado sea dueño u tenga permiso sobre ese objeto. El atacante simplemente cambia el ID en la request (`?id=42` → `?id=43`) y accede al recurso de otro usuario. Subset de Broken Access Control (OWASP A01:2021), categorizado como BOLA en API Security Top 10. Pattern del mismo tipo: el server confía en input del cliente como autoridad de identidad/ownership, sin derivar el target de la sesión.

## Categorías de IDs explotables

- **Numéricos secuenciales**: `?orderId=1234` → enumerar órdenes de otros users incrementando.
- **Usernames**: `?id=carlos` → acceso a perfil de carlos (caso del lab `user-id-controlled-by-request-parameter`).
- **UUIDs predecibles**: UUID v1 incluye timestamp + MAC, predecible si conocés un vecino. UUID v4 random es seguro (entropía suficiente).
- **Hashes débiles**: hashes de strings comunes (`md5(username)`) reversibles con rainbow tables.
- **Slugs publicos**: el sistema expone IDs de objetos a un user pero asume otros users no los conocen (falso, leakean por compartido, scrapeo, búsqueda).

## Categorías de objetos típicamente afectados

- **Account/profile data**: API keys, email, dirección, payment methods.
- **Documents/files**: invoices, contracts, médical records.
- **Orders**: ver/cancelar órdenes de otros usuarios.
- **Messages**: leer DMs entre otros users.
- **Admin actions**: si se combinan con missing function-level authz, escalada vertical (`?action=delete&id=victim`).

## Herramientas
- **Burp Suite (Repeater + Intruder)**: tampering manual y enumeración automática de IDs.
- **Burp Suite (Authorize plugin)**: testing automatizado comparando respuesta auth-as-A vs auth-as-B vs anonymous.
- **ffuf con range payload**: enumerar IDs numéricos rápido (`-w <(seq 1 10000):IDX`).
- **Browser DevTools**: Network tab para ver IDs en URLs/JSON responses.
- **autorize / auto-repeater**: extensiones Burp para regression testing de access control.

## Comandos / Ejemplos

### Tampering manual de un ID
```bash
# URL legitima del usuario
curl 'https://target/my-account?id=wiener' -H 'Cookie: session=...'

# IDOR: cambiar id a otro user
curl 'https://target/my-account?id=carlos' -H 'Cookie: session=...'
# Si responde 200 con datos de carlos, vuln confirmada
```

### Enumeración numérica con Intruder
```
# Burp Intruder
Target: GET /api/orders/§1§ HTTP/2
Payload: Numbers, 1 to 10000, Step 1

# Si la mayoría devuelve 200 con datos sensibles, IDOR masiva.
```

### Enumeración de UUIDs v1 (basado en timestamp)
```python
# Si conocés un UUID legitimo de hace t segundos, generar variantes cercanas
import uuid
known = uuid.UUID("a1b2c3d4-1234-1234-1234-1234567890ab")
# UUID v1 timestamp esta en bytes 0-3 + parte de 4-5
# Decrementar/incrementar timestamp y probar
```

### Detección por header oracle
```bash
# Algunos endpoints aceptan ID en header en lugar de URL
curl 'https://target/api/me' -H 'Cookie: session=...' -H 'X-User-Id: 123'
# Si respeta el header sobre la session, IDOR via header.
```

## Contramedidas
- **Authz check server-side por objeto**: cada query a un recurso valida que `recurso.owner_id == session.user_id` (o que el user tenga rol/permission).
- **Sesiones derivan identity, no del cliente**: el target user/object se infiere de la sesión, no de un parámetro del request. Si necesitás multi-user (admin viendo perfiles de otros), permission check explícito.
- **IDs random/UUID v4**: si tenés que exponer IDs, usar UUID v4 (entropía 122 bits, no enumerable). Pero esto es defensa-en-profundidad; la auth en cada query es lo principal.
- **Indirection layer** (URL handles per-session): en lugar de exponer DB IDs reales, generar tokens random por sesión que mapean a IDs internos. El cliente nunca ve el ID real.
- **Audit logging** de acceso a recursos: detectar enumeración (mismo user accediendo a 100 IDs distintos en pocos minutos).
- **Tests automatizados de access control**: por cada endpoint de recurso, test que verifica usuario A no puede leer/modificar recurso de usuario B.
- **Rate-limiting** en endpoints que aceptan ID variable: previene enumeración masiva, no la elimina.

## Referencias
- OWASP Foundation. (2021). *A01:2021 - Broken Access Control*. https://owasp.org/Top10/A01_2021-Broken_Access_Control/
- OWASP Foundation. (s.f.). *API1:2023 Broken Object Level Authorization*. https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/
- OWASP Foundation. (s.f.). *Authorization Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
- OWASP Foundation. (s.f.). *Insecure Direct Object Reference Prevention Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy. (s.f.). *Insecure direct object references*. https://portswigger.net/web-security/access-control/idor
- MITRE Corporation. (2024). *CWE-639: Authorization Bypass Through User-Controlled Key*. https://cwe.mitre.org/data/definitions/639.html
- MITRE Corporation. (2024). *CWE-284: Improper Access Control*. https://cwe.mitre.org/data/definitions/284.html
- MITRE Corporation. (2024). *CWE-285: Improper Authorization*. https://cwe.mitre.org/data/definitions/285.html
- MITRE Corporation. (2024). *ATT&CK Technique T1190: Exploit Public-Facing Application*. https://attack.mitre.org/techniques/T1190/
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook* (2nd ed.). Wiley. Cap. 8 (Attacking Access Controls).
- Hoffman, A. (2020). *Web Application Security*. O'Reilly. Cap. 16 (Authorization).
