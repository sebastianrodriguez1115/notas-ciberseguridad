---
title: Detección de WAF
slug: deteccion-waf
aliases: [WAF Detection, Web Application Firewall Detection, wafw00f]
fase: [Reconocimiento]
plataforma: Web
dificultad: Intermedia
mitre: [T1595]
related: [fingerprinting-tecnologias-web, fingerprinting-tecnologias-web-activo]
learning_refs: []
---

# Detección de WAF (Web Application Firewall)

## Descripción
Identificación de Web Application Firewalls que protegen las aplicaciones web del objetivo. Según *Gray Hat Hacking*, la detección no solo sirve para identificar el producto, sino para determinar el **umbral de bloqueo** y los métodos de evasión (bypass). Técnicas avanzadas incluyen el uso de **encodings no convencionales** (ej: IBM037) y la manipulación del campo `Transfer-Encoding: chunked` para confundir al WAF.

## Herramientas
- **wafw00f** — Herramienta lider en detección e identificación por huellas dactilares (cookies, headers, respuestas)
- **whatwaf** — Detección de WAF que propone payloads de bypass específicos
- **nmap (script http-waf-detect)** — Detección de WAF mediante NSE scripts

## Comandos / Ejemplos

### Detección Básica de WAF con wafw00f
```bash
wafw00f https://target.com
```

### Detección Manual por Cookies y Headers (Libros de referencia)
- **Cloudflare**: Presencia del header `CF-RAY`, header `server: cloudflare` y paginas de challenge JavaScript.
- **Akamai**: Headers que comienzan con `X-Akamai-`.
- **Sucuri**: Headers como `X-Sucuri-ID` o `X-Sucuri-Cache`.

### Detección via Timing Attack (Silenciosa)
Observar aumentos en el tiempo de respuesta al enviar payloads que requieren procesamiento intensivo en el WAF (ej: payloads complejos de Regex), incluso si la respuesta final es un 403.

### Intento de Evasión via Chunked Transfer
```bash
# Ejemplo de petición HTTP manual
POST /search HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

1
A
1
B
0
```
Esta técnica puede evadir WAFs que no reconstruyen el cuerpo de la petición antes de realizar la inspección.

## Contramedidas
- **Desactivar Headers de Identificación**: Configurar el WAF para no añadir sus propios headers a la respuesta.
- **Normalizar Respuestas de Bloqueo**: Utilizar paginas de error 403 genéricas.
- **Limitar Rate de Peticiones**: Para evitar que atacantes mapeen las reglas de bloqueo mediante ataques de fuerza bruta.

## Referencias
- Harper, A., Harris, S., Ness, J., Eagle, C., Lenkey, G., & Williams, T. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
- EnableSecurity. (s.f.). *wafw00f* [Software]. GitHub. https://github.com/EnableSecurity/wafw00f
- MITRE Corporation. (2024). ATT&CK Technique T1595: Active Scanning. https://attack.mitre.org/techniques/T1595/
