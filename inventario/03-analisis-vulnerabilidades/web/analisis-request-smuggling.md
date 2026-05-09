---
title: Análisis de HTTP Request Smuggling
slug: analisis-request-smuggling
aliases: [HTTP Request Smuggling, HTTP Desync, CL.TE, TE.CL, TE.TE]
fase: [Análisis de Vulnerabilidades]
plataforma: Web
dificultad: Avanzada
mitre: [T1190]
related: []
learning_refs: [portswigger/confirming-cl-te-via-differential-responses, portswigger/confirming-te-cl-via-differential-responses]
---

# Análisis de HTTP Request Smuggling

## Descripción

HTTP Request Smuggling (también HTTP Desync) es una vulnerabilidad de la frontera entre dos servidores HTTP encadenados (típicamente front-end CDN/proxy + back-end app server) que parsean el body de una request con reglas distintas. Cuando el cliente envía headers ambiguos sobre el tamaño del body (`Content-Length` y `Transfer-Encoding: chunked` simultáneamente), cada servidor interpreta una cantidad de bytes diferente. El delta queda en el socket TCP keep-alive y se prepende a la siguiente request en esa conexión, permitiendo que un atacante "smuggle" una request maliciosa que afecta a la siguiente víctima.

A diferencia de bugs de aplicación clásicos, smuggling no requiere fallas en el código de la app — opera enteramente sobre la implementación del protocolo HTTP/1.1 entre los servidores.

### Variantes principales

- **CL.TE**: front-end usa `Content-Length`, back-end usa `Transfer-Encoding: chunked`. Front-end forwardea N bytes; back-end consume M < N por chunked terminator; los `N - M` sobrantes son "smuggled".
- **TE.CL**: front-end usa `Transfer-Encoding`, back-end usa `Content-Length`. Front-end lee chunked completo; back-end solo lee CL bytes; chunks no leídos quedan en socket.
- **TE.TE**: ambos usan `Transfer-Encoding`, pero uno solo entiende una variante obfuscada (`Transfer-Encoding: chunked\r\nTransfer-Encoding: x`); el que falla cae a CL implícito.

### Impactos derivados

Smuggling es vector hacia explotación adicional, no impact por sí solo:

- **Bypass de controles del front-end**: requests smuggled saltan validación de WAF, rate limiting, headers de routing.
- **Captura de requests de otros usuarios**: smuggled prefix concatena el inicio de la siguiente request (incluyendo cookies de sesión) con el body de la request del atacante.
- **Cache poisoning**: smuggled prefix induce que la response del backend se asocie a un path distinto en el cache CDN.
- **Acceso administrativo**: smuggled prefix con headers internos (`X-Forwarded-For: 127.0.0.1`) puede acceder endpoints restringidos.

## Herramientas

- **Burp Suite Repeater** — construir manualmente el payload con HTTP/1, sin auto-update de Content-Length.
- **Burp Suite Pro Scanner** — extensión "HTTP Request Smuggler" detecta CL.TE/TE.CL automáticamente.
- **smuggler** ([defparam/smuggler](https://github.com/defparam/smuggler)) — herramienta CLI que prueba decenas de payloads de obfuscación contra un endpoint.
- **smuggler.py** ([anshumanbh/smuggler](https://github.com/anshumanbh/smuggler)) — alternativa Python.
- **h2c-smuggler** — para variantes HTTP/2 → HTTP/1 downgrade smuggling.

## Comandos / Ejemplos

### Detección via differential responses (CL.TE)

```http
POST / HTTP/1.1
Host: target.example.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```

Body de 35 bytes exactos: `0\r\n\r\nGET /404 HTTP/1.1\r\nX-Ignore: X` (sin CRLF final). Mandar dos veces consecutivas con keep-alive. Si la segunda response es 404 (en lugar del 200 esperado), es CL.TE.

### Detección via timing (CL.TE)

```http
POST / HTTP/1.1
Host: target.example.com
Content-Length: 4
Transfer-Encoding: chunked

1
A
X
```

Front-end (CL=4) lee `1\r\nA` (4 bytes), forwardea. Back-end (TE) parsea chunk size 1, lee `A`, espera siguiente chunk → no llega → timeout largo. Diferencia de tiempo confirma desync.

### Variante TE.CL

```http
POST / HTTP/1.1
Host: target.example.com
Content-Length: 3
Transfer-Encoding: chunked

8
SMUGGLED
0


```

Front-end (TE) lee chunk 8, lee `SMUGGLED`, lee chunk 0 → fin. Back-end (CL=3) lee solo `8\r\n` y considera body terminado; el resto es prefix smuggled.

### Obfuscación TE.TE

```
Transfer-Encoding: chunked
Transfer-Encoding: x
```

Algunos parsers solo leen el primer header, otros el último. La discrepancia determina cuál servidor falla a CL implícito.

```
Transfer-Encoding: xchunked
Transfer-Encoding:[tab]chunked
Transfer-Encoding : chunked
```

Variantes con whitespace, prefijos, separadores no estándar. PayloadsAllTheThings tiene catálogo completo.

### Detección automatizada con smuggler

```bash
python3 smuggler.py -u https://target.example.com/
# Prueba ~30 payloads de obfuscación, reporta los que producen response anómala
```

## Contramedidas

- **Usar HTTP/2 entre front-end y back-end**: bodies framed binariamente, sin ambigüedad CL/TE. Cierra la categoría por construcción.
- **Rechazar requests con CL y TE simultáneos** en el front-end con 400 Bad Request. La normalización (ignorar uno) es la causa del bug; rechazar es más seguro.
- **Sin keep-alive entre front-end y back-end**: cada request abre conexión nueva. Sin socket compartido, los bytes "smuggled" no llegan a otra request. Costo: latencia + file descriptors.
- **Validación estricta del parser HTTP del back-end**: rechazar headers contradictorios o mal formados. Implementaciones modernas (Node 18+, Go net/http reciente, Tomcat 10+) lo hacen.
- **Same-software end-to-end**: si front-end y back-end son la misma versión de Nginx/Apache, los parsers son idénticos, no hay gap por construcción.
- **WAF con reglas específicas**: detectar combinaciones de headers anómalas, encodings obfuscados, payloads con `0\r\n\r\n` seguido de método HTTP. Defensa-en-profundidad.
- **Tests de regresión en CI**: ejecutar `smuggler` o Burp Smuggler contra staging pre-deploy para prevenir reaparición del bug.

## Referencias

- PortSwigger Research. (2019). *HTTP Desync Attacks: Request Smuggling Reborn* (James Kettle). https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
- PortSwigger Web Security Academy. (s.f.). *HTTP request smuggling*. https://portswigger.net/web-security/request-smuggling
- IETF. (2022). *RFC 9112: HTTP/1.1*. https://datatracker.ietf.org/doc/html/rfc9112
- OWASP Foundation. (s.f.). *HTTP Request Smuggling*. https://owasp.org/www-community/attacks/HTTP_Request_Smuggling
- MITRE Corporation. (2024). *CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')*. https://cwe.mitre.org/data/definitions/444.html
- MITRE Corporation. (2024). *ATT&CK Technique T1190: Exploit Public-Facing Application*. https://attack.mitre.org/techniques/T1190/
- swisskyrepo. (s.f.). *PayloadsAllTheThings — Request Smuggling*. https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling
- defparam. (s.f.). *smuggler — HTTP Request Smuggling detection tool* [Software]. GitHub. https://github.com/defparam/smuggler
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook* (2nd ed.). Wiley. Cap. 17 (Attacking Application Architecture).
- Hoffman, A. (2020). *Web Application Security: Exploitation and Countermeasures for Modern Web Applications*. O'Reilly Media.
