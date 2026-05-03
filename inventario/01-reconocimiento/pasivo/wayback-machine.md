---
title: Wayback Machine
slug: wayback-machine
aliases: [Internet Archive, archive.org, Web Archive, gau, waybackurls]
fase: [Reconocimiento]
plataforma: Web
dificultad: Básica
mitre: [T1593]
related: [google-dorking, fingerprinting-tecnologias-web]
learning_refs: []
---

# Wayback Machine

## Descripción
Acceso a snapshots historicos de sitios web a través del archivo de Internet Archive. Según *The Hacker Playbook 3*, la Wayback Machine es una mina de oro para el reconocimiento, ya que permite encontrar **versiones antiguas de archivos JavaScript** que contienen endpoints de API que siguen funcionales pero ya no están documentados, o incluso **API keys** que fueron expuestas y eliminadas pero permanecen en el archivo historico.

## Herramientas
- **Wayback Machine** (web.archive.org) — Repositorio historico mundial de la web
- **waybackurls** — Extrae URLs de dominios específicos desde el archivo
- **gau (Get All Urls)** — Combina Wayback, Common Crawl y AlienVault OTX para una recolección más exhaustiva
- **mantra** — Herramienta para extraer secretos (API keys, tokens) de archivos JS recolectados

## Comandos / Ejemplos

### Extracción de URLs Historicas con gau
```bash
gau target.com | sort -u > urls_historicas.txt
```

### Análisis de Secretos en JavaScript Historico
```bash
gau target.com | grep "\.js$" | xargs curl -s | mantra
```
Esta técnica permite descubrir tokens de servicios (AWS, Stripe, Firebase) que fueron accidentalmente subidos a producción y luego borrados, pero que permanecen en los snapshots de Wayback.

### Búsqueda de Endpoints de API Antiguos
```bash
waybackurls target.com | grep -iE "(v1|v2|api|graphql|rest)" | sort -u
```
Identifica versiones antiguas de APIs que podrian carecer de las medidas de seguridad (como MFA o rate limiting) implementadas en las versiones actuales.

### Descubrimiento de Parametros para Fuzzing
```bash
waybackurls target.com | grep "=" | sort -u | sed 's/=.*$/=/'
```
Extrae los nombres de los parametros historicos para alimentar herramientas de fuzzing como `ffuf` o `sqlmap`.

## Contramedidas
- **Descomisionar Endpoints Antiguos**: Asegurarse de que las versiones viejas de la API ya no esten accesibles en el servidor actual.
- **Rotar Secretos Expuestos**: Si una API key se subio accidentalmente al sitio web, se debe considerar **comprometida para siempre** y rotarla de inmediato.
- **Solicitar Eliminación de Snapshots**: En casos extremos de exposición de datos sensibles, se puede solicitar a Internet Archive la eliminación de snapshots específicos.

## Referencias
- Kim, P. (2018). *The Hacker Playbook 3: Practical Guide to Penetration Testing*. Secure Planet.
- MITRE Corporation. (2024). ATT&CK Technique T1593: Search Open Websites/Domains. https://attack.mitre.org/techniques/T1593/
- Internet Archive. (s.f.). *Wayback Machine*. https://web.archive.org/
