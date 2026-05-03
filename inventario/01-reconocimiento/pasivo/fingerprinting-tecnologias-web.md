# Fingerprinting Pasivo de Tecnologías Web

## Descripción
Identificación del stack tecnológico de una aplicación web (servidor HTTP, framework, CMS, lenguaje, librerías) **sin enviar peticiones directas al objetivo**. Se apoya en servicios de terceros que ya han indexado al objetivo (BuiltWith, Wappalyzer cloud, Stackshare), historiales públicos (archive.org, certificate transparency), y análisis de artefactos JavaScript previamente descargados (Retire.js sobre archivos locales). El valor estratégico es el sigilo: el objetivo no detecta ningún tráfico relacionado con el reconocimiento.

> **Variante activa**: para fingerprinting que envía peticiones al objetivo (WhatWeb, httpx, Wappalyzer CLI), ver [`02-enumeracion/web/fingerprinting-tecnologias-web.md`](../../02-enumeracion/web/fingerprinting-tecnologias-web.md).

## Clasificación
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: [T1592.002](https://attack.mitre.org/techniques/T1592/002/) (Gather Victim Host Information: Software)
- **Plataforma**: Web
- **Dificultad**: Básica

## Herramientas
- **BuiltWith** (`builtwith.com`) — Perfil tecnológico completo del objetivo basado en datos pre-recolectados; incluye historial de cambios de stack
- **Wappalyzer** (extensión de navegador / API) — En modo extensión analiza la página que tu navegador ya está cargando; en modo API consulta su base de datos pre-indexada
- **Stackshare** (`stackshare.io`) — Tecnologías auto-declaradas por empresas en perfiles públicos
- **Retire.js** — Escanea archivos JavaScript **locales** (descargados previamente) buscando librerías con CVEs conocidos
- **crt.sh** + **archive.org** — Cabeceras y código fuente histórico para inferir tecnologías sin tocar el sitio actual

## Comandos / Ejemplos

### BuiltWith (perfil completo desde fuera)
- Navegar a `https://builtwith.com/<dominio>` o usar la API.
- Información típica: servidor HTTP, framework, CMS, proveedor de autenticación (Okta, Auth0), CDN (Cloudflare, Akamai), analytics, e-commerce.
- Útil para identificar dependencias de terceros que pueden ser vectores de ataque indirectos (supply chain).

### Detección de Infraestructura DevOps a través de OSINT
Sin enviar peticiones, varios indicadores son extraíbles de fuentes públicas:
- **Kubernetes**: shodan o censys filtrando por `port:6443` o `port:10250`.
- **Docker expuesto**: shodan filtrando por `port:2375` o `port:2376`.
- **Envoy/Istio**: aparecen en cabeceras (`server: envoy`) ya capturadas por crawlers públicos.

### Análisis de JS descargado con Retire.js
```bash
# Tras haber descargado los archivos JS del sitio (no envía peticiones nuevas)
retire --js --jspath /path/to/downloaded/js/
```
Identifica librerías de terceros con CVEs conocidos (jQuery vulnerable, Angular antiguo, etc.). El input es archivos locales, no el sitio en vivo.

### Wappalyzer (modo extensión)
Al visitar el objetivo en un navegador con Wappalyzer instalado, el plugin analiza el DOM y cabeceras de la página que tu navegador ya cargó. No emite peticiones adicionales. Se considera pasivo bajo el criterio "no genera tráfico extra al objetivo".

> Nota: Wappalyzer en modo CLI **sí envía peticiones** y por tanto es activo. Ver el archivo de fase 2.

## Contramedidas
- **Solicitar la eliminación del perfil en BuiltWith / Wappalyzer / Stackshare** si la organización quiere reducir la huella pública (parcialmente efectivo, los datos suelen reaparecer)
- **Normalizar cabeceras HTTP** salientes (`Server`, `X-Powered-By`, `X-Generator`) para que crawlers no las indexen
- **Minificar JavaScript** y eliminar comentarios/strings que revelen versiones de librerías
- **Subresource Integrity (SRI)** para librerías de terceros, que también reduce la superficie de scrapping
- **Monitorizar menciones de la organización** en Stackshare y plataformas similares para detectar leaks involuntarios de stack interno (job postings que mencionan tecnologías)

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Matherly, J. (2017). *Complete Guide to Shodan*. Leanpub.
- MITRE Corporation. (2024). ATT&CK Technique T1592.002: Gather Victim Host Information: Software. https://attack.mitre.org/techniques/T1592/002/
