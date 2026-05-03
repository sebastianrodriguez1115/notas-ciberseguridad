---
title: Fingerprinting Activo de Tecnologías Web
slug: fingerprinting-tecnologias-web-activo
aliases: [Fingerprinting Activo de Tecnologías Web, Active Tech Fingerprinting, WhatWeb, httpx, Wappalyzer CLI]
fase: [Enumeración]
plataforma: Web
dificultad: Básica
mitre: [T1592.002, T1592]
related: [fingerprinting-tecnologias-web, banner-grabbing-http, deteccion-waf]
learning_refs: []
---

# Fingerprinting Activo de Tecnologías Web

## Descripción
Identificación del stack tecnológico de una aplicación web (servidor HTTP, framework, CMS, lenguaje de programación y versiones) **enviando peticiones directas al objetivo**. Las herramientas analizan cabeceras HTTP, cookies, estructura del HTML, recursos cargados y respuestas a probes específicos para inferir las tecnologías subyacentes. Es esencial para priorizar vectores de ataque y buscar CVEs específicos para las versiones detectadas. La contrapartida del sigilo es la precisión: las versiones exactas suelen revelarse sólo con peticiones probing.

> **Variante pasiva**: para fingerprinting sin enviar peticiones (BuiltWith, Wappalyzer cloud, Retire.js sobre JS local), ver [`01-reconocimiento/pasivo/fingerprinting-tecnologias-web.md`](../../01-reconocimiento/pasivo/fingerprinting-tecnologias-web.md).

## Herramientas
- **WhatWeb** — fingerprinting activo desde CLI; detecta servidor, CMS, frameworks, versiones, plugins
- **httpx** — verificación de host vivo, extracción de cabeceras, fingerprinting básico, soporte para pipelines
- **Wappalyzer CLI** — modo línea de comandos (a diferencia de la extensión, este sí envía peticiones)
- **nmap NSE** — scripts `http-enum`, `http-headers`, `http-server-header` para fingerprinting integrado en el flujo nmap
- **curl** — inspección manual de cabeceras y respuestas, útil para confirmar resultados automatizados

## Comandos / Ejemplos

### WhatWeb (fingerprinting activo desde CLI)
```bash
# Fingerprinting básico
whatweb http://target.com
whatweb 10.4.18.13

# Mayor agresividad (nivel 3 envía peticiones adicionales para confirmar versiones de CMS y plugins)
whatweb -a 3 https://target.com

# Salida JSON para integrar con otras herramientas
whatweb --log-json=output.json https://target.com
```

### httpx (verificación de hosts vivos + cabeceras)
```bash
# Verificar que un host responde
httpx https://app.target.com

# Pipeline con subfinder para verificar subdominios vivos
cat subdominios.txt | httpx | sort -u > activos_vivos.txt

# Mostrar tecnologías detectadas y status code
httpx -tech-detect -status-code -title -l dominios.txt
```

### Detección de Infraestructura DevOps con probes activos
Endpoints específicos que revelan tecnologías de orquestación cuando son accesibles:
- **Kubernetes API**: `https://target:6443/api` y `https://target:10250/metrics`
- **Docker daemon expuesto**: `http://target:2375/version` (TCP sin cifrar) o TLS en 2376
- **Envoy admin**: `/clusters`, `/server_info` si el admin endpoint está expuesto
- **Cabeceras HTTP delatoras**: `server: envoy`, `x-envoy-upstream-service-time`, `x-kubernetes-edge`

### nmap NSE para fingerprinting HTTP
```bash
# Identificación del servidor HTTP y headers
nmap -p 80,443 --script=http-headers,http-server-header target.com

# Enumeración de aplicaciones web conocidas (WordPress, Drupal, etc.)
nmap -p 80,443 --script=http-enum target.com
```

### Inspección manual con curl
```bash
# Cabeceras completas
curl -I https://target.com

# Probing de tecnología específica
curl -s https://target.com/wp-login.php -o /dev/null -w "%{http_code}"     # ¿WordPress?
curl -s https://target.com/.env -o /dev/null -w "%{http_code}"             # ¿.env expuesto?
curl -sk https://target.com/server-status                                  # ¿Apache mod_status?
```

**Cabeceras HTTP relevantes a inspeccionar:**
```
Server: Apache/2.4.29 (Ubuntu)
X-Powered-By: PHP/7.2.10
X-Generator: Drupal 8
X-AspNet-Version: 4.0.30319
Set-Cookie: PHPSESSID=...; JSESSIONID=...
```

## Contramedidas
- Eliminar o falsificar cabeceras `Server`, `X-Powered-By`, `X-Generator`, `X-AspNet-Version` en la configuración del servidor
- Deshabilitar cabeceras que revelan versión (`ServerTokens Prod` en Apache, `server_tokens off` en Nginx)
- Usar un WAF o reverse proxy que normalice las cabeceras de respuesta a un valor común
- Mantener software actualizado para que incluso si se detecta la versión no haya CVEs explotables
- Bloquear acceso externo a endpoints de orquestación (Kubernetes API, Docker daemon, Envoy admin)
- Rate limiting para mitigar fingerprinting por probing masivo

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook* (2nd ed.). Wiley.
- MITRE Corporation. (2024). ATT&CK Technique T1592.002: Gather Victim Host Information: Software. https://attack.mitre.org/techniques/T1592/002/
