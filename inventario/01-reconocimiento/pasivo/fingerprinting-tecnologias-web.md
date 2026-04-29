# Fingerprinting de Tecnologias Web

## Descripcion
Identificacion de tecnologias web, frameworks, CMS, software de servidor y servicios de terceros. Segun *Mastering Kali Linux*, el fingerprinting moderno se enfoca en detectar el **stack DevOps** (Docker, Kubernetes) y los **microservicios** que componen la aplicacion. La deteccion se basa en el analisis de cabeceras HTTP personalizadas, estructura de cookies y metadatos en el codigo fuente.

## Clasificacion
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: T1592.002 (Gather Victim Host Information: Software)
- **Plataforma**: Web
- **Dificultad**: Basica

## Herramientas
- **Wappalyzer** — Extension de navegador y herramienta CLI para deteccion automatica
- **WhatWeb** — Herramienta CLI versatil para fingerprinting web masivo
- **BuiltWith** — Perfil tecnologico completo y servicios de infraestructura (hosting, CDN)
- **Retire.js** — Especializada en detectar librerias JavaScript vulnerables o desactualizadas

## Comandos / Ejemplos

### Deteccion de Infraestructura DevOps
- **Kubernetes**: Headers como `X-Kubernetes-Edge` o puertos 6443/10250.
- **Docker**: Puertos 2375 (TCP sin cifrar) o 2376 (TLS).
- **Envoy/Istio**: Headers `server: envoy` o `x-envoy-upstream-service-time`.

### Fingerprinting con WhatWeb
```bash
whatweb -a 3 https://target.com
```
La agresividad nivel 3 envia peticiones adicionales para confirmar versiones de CMS y frameworks.

### Identificacion de Librerias JS Vulnerables (Retire.js)
```bash
retire --js --jspath /path/to/downloaded/js/
```
Escanea archivos JavaScript locales (previamente descargados del objetivo) buscando librerias de terceros con CVEs conocidos, facilitando la fase de analisis de vulnerabilidades.

### BuiltWith (Tecnologias de terceros)
Proporciona visibilidad sobre que proveedores de autenticacion (Okta, Auth0) o CDN (Cloudflare, Akamai) utiliza el objetivo.

## Contramedidas
- **Normalizar Cabeceras**: Eliminar cabeceras informativas (Server, X-Powered-By, X-AspNet-Version).
- **Eliminar Metadatos**: Limpiar el HTML de comentarios de desarrollador y metadatos de frameworks (ej: `generator`).
- **Minificacion de Codigo**: Dificulta la identificacion de versiones especificas de librerias JS.
- **WAF**: Utilizar reglas para ofuscar o normalizar las firmas tecnologicas salientes.

## Referencias
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1592.002: Gather Victim Host Information: Software. https://attack.mitre.org/techniques/T1592/002/
