# Wayback Machine

## Descripcion
Acceso a snapshots historicos de sitios web a traves del archivo de Internet Archive. Segun *The Hacker Playbook 3*, la Wayback Machine es una mina de oro para el reconocimiento, ya que permite encontrar **versiones antiguas de archivos JavaScript** que contienen endpoints de API que siguen funcionales pero ya no estan documentados, o incluso **API keys** que fueron expuestas y eliminadas pero permanecen en el archivo historico.

## Clasificacion
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: T1593 (Search Open Websites/Domains)
- **Plataforma**: Web
- **Dificultad**: Basica

## Herramientas
- **Wayback Machine** (web.archive.org) — Repositorio historico mundial de la web
- **waybackurls** — Extrae URLs de dominios especificos desde el archivo
- **gau (Get All Urls)** — Combina Wayback, Common Crawl y AlienVault OTX para una recoleccion mas exhaustiva
- **mantra** — Herramienta para extraer secretos (API keys, tokens) de archivos JS recolectados

## Comandos / Ejemplos

### Extraccion de URLs Historicas con gau
```bash
gau target.com | sort -u > urls_historicas.txt
```

### Analisis de Secretos en JavaScript Historico
```bash
gau target.com | grep "\.js$" | xargs curl -s | mantra
```
Esta tecnica permite descubrir tokens de servicios (AWS, Stripe, Firebase) que fueron accidentalmente subidos a produccion y luego borrados, pero que permanecen en los snapshots de Wayback.

### Busqueda de Endpoints de API Antiguos
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
- **Solicitar Eliminacion de Snapshots**: En casos extremos de exposicion de datos sensibles, se puede solicitar a Internet Archive la eliminacion de snapshots especificos.

## Referencias
- Kim, P. (2018). *The Hacker Playbook 3: Practical Guide to Penetration Testing*. Secure Planet.
- Notas del proyecto: notas-md/HNotes/Recon/Passive Enumeration/Wayback URLs.md
- MITRE Corporation. (2024). ATT&CK Technique T1593: Search Open Websites/Domains. https://attack.mitre.org/techniques/T1593/
- Internet Archive. (s.f.). *Wayback Machine*. https://web.archive.org/
