# Deteccion de WAF (Web Application Firewall)

## Descripcion
Identificacion de Web Application Firewalls que protegen las aplicaciones web del objetivo. Segun *Gray Hat Hacking*, la deteccion no solo sirve para identificar el producto, sino para determinar el **umbral de bloqueo** y los metodos de evasion (bypass). Tecnicas avanzadas incluyen el uso de **encodings no convencionales** (ej: IBM037) y la manipulacion del campo `Transfer-Encoding: chunked` para confundir al WAF.

## Clasificacion
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: T1595 (Active Scanning)
- **Plataforma**: Web
- **Dificultad**: Intermedia

## Herramientas
- **wafw00f** — Herramienta lider en deteccion e identificacion por huellas dactilares (cookies, headers, respuestas)
- **whatwaf** — Deteccion de WAF que propone payloads de bypass especificos
- **nmap (script http-waf-detect)** — Deteccion de WAF mediante NSE scripts

## Comandos / Ejemplos

### Deteccion Basica de WAF con wafw00f
```bash
wafw00f https://target.com
```

### Deteccion Manual por Cookies y Headers (Libros de referencia)
- **Cloudflare**: Presencia del header `CF-RAY`, header `server: cloudflare` y paginas de challenge JavaScript.
- **Akamai**: Headers que comienzan con `X-Akamai-`.
- **Sucuri**: Headers como `X-Sucuri-ID` o `X-Sucuri-Cache`.

### Deteccion via Timing Attack (Silenciosa)
Observar aumentos en el tiempo de respuesta al enviar payloads que requieren procesamiento intensivo en el WAF (ej: payloads complejos de Regex), incluso si la respuesta final es un 403.

### Intento de Evasion via Chunked Transfer
```bash
# Ejemplo de peticion HTTP manual
POST /search HTTP/1.1
Host: target.com
Transfer-Encoding: chunked

1
A
1
B
0
```
Esta tecnica puede evadir WAFs que no reconstruyen el cuerpo de la peticion antes de realizar la inspeccion.

## Contramedidas
- **Desactivar Headers de Identificacion**: Configurar el WAF para no añadir sus propios headers a la respuesta.
- **Normalizar Respuestas de Bloqueo**: Utilizar paginas de error 403 genericas.
- **Limitar Rate de Peticiones**: Para evitar que atacantes mapeen las reglas de bloqueo mediante ataques de fuerza bruta.

## Referencias
- Harper, A., Harris, S., Ness, J., Eagle, C., Lenkey, G., & Williams, T. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
- Notas del proyecto: notas-md/INE Courses/Assessment Methodologies Information Gathering/Passive Information Gathering.md
- EnableSecurity. (s.f.). *wafw00f* [Software]. GitHub. https://github.com/EnableSecurity/wafw00f
- MITRE Corporation. (2024). ATT&CK Technique T1595: Active Scanning. https://attack.mitre.org/techniques/T1595/
