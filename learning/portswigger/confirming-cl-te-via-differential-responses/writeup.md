# Writeup: HTTP request smuggling, confirming a CL.TE vulnerability via differential responses (PortSwigger)

- **Lab**: HTTP request smuggling, confirming a CL.TE vulnerability via differential responses
- **URL**: https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses
- **Categoría**: HTTP Request Smuggling / CL.TE desync / Detection
- **Dificultad**: Practitioner

---

## 1. Objetivo

Confirmar que el sitio tiene desincronización CL.TE entre el front-end y el back-end. Front-end usa `Content-Length`, back-end usa `Transfer-Encoding: chunked`. La confirmación se hace observando que una request mandada dos veces produce una respuesta diferente la segunda vez (o, como pasó en este lab, ambas respuestas son `404` cuando la primera "limpia" devolvería `200`).

Payload final (HTTP/1.1 sobre Burp Repeater, con Update-Content-Length **desactivado**):

```http
POST / HTTP/1.1
Host: 0a3a001f044ecb238004129b00cd006d.web-security-academy.net
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

0

GET /404 HTTP/1.1
X-Ignore: X
```

Body de 35 bytes exactos: `0\r\n\r\nGET /404 HTTP/1.1\r\nX-Ignore: X` (sin CRLF final). Ambos envíos retornan `404 Not Found` con cuerpo `"Not Found"`.

### Insight central

**Request smuggling es un bug de la frontera entre dos servidores HTTP que parsean el body con reglas distintas**. CL.TE significa que el front-end delimita el body por `Content-Length` mientras el back-end delimita por chunked encoding. Mandar headers contradictorios crea un gap: el front-end forwardea N bytes, el back-end consume M < N bytes, los `N - M` sobrantes quedan en el socket TCP del backend y se prependen a la siguiente request en esa misma conexión. La novedad sobre otros bugs HTTP es que la victima del gap es **otra request en el mismo socket**, lo cual permite atacar a otros usuarios sin tocar su tráfico directamente.

---

## 2. Recon y resolución

### 2.1 Setup de Burp para HTTP/1

El bug requiere HTTP/1.1 — HTTP/2 binariza el body con frames de longitud explícita y no permite ambigüedad CL/TE. Burp por default upgradeaba a HTTP/2 contra el lab. Pasos:

1. Capturar cualquier POST del sitio (en este caso `/post/comment` natural). Mandar al Repeater.
2. En el Repeater: settings (ícono de la llave inglesa) → desmarcar **"Update Content-Length"**. El payload depende de un CL controlado a mano que NO matchea el body real.
3. Inspector del request o "..." menú → cambiar a **HTTP/1**. Burp muestra "HTTP/1.1" en el target details.
4. Reemplazar el contenido del Repeater por el payload completo.

### 2.2 Construir el payload

Header del request:

```
POST / HTTP/1.1
Host: <lab>
Content-Type: application/x-www-form-urlencoded
Content-Length: 35
Transfer-Encoding: chunked

```

Body crudo (CRLF entre líneas, sin CRLF al final del último `X`):

```
0
                ← línea vacía (CRLF doble): primer chunk size (0) + terminator
GET /404 HTTP/1.1
X-Ignore: X
```

Conteo byte por byte:

| Bytes | Contenido |
|-------|-----------|
| 1 | `0` |
| 2 | `\r\n` |
| 2 | `\r\n` (chunked terminator: chunk size 0 + línea vacía) |
| 17 | `GET /404 HTTP/1.1` |
| 2 | `\r\n` |
| 11 | `X-Ignore: X` |
| **35** | **total** |

Crítico: NO agregar `\r\n` después del `X` final. Burp puede agregarlo automático y el body pasa a 37 bytes; con CL=35 el front-end leería solo 35 y los 2 bytes restantes quedarían en el socket del front-end (no del back-end), lo cual no crea el smuggle deseado.

### 2.3 Enviar y observar

Mandar el request dos veces consecutivas. Tiempo entre envíos importa — si pasa demasiado, el back-end puede cerrar el socket por inactividad y los bytes "smuggled" se pierden.

Resultados:

```
1er envío: 404 Not Found, "Not Found"
2do envío: 404 Not Found, "Not Found"
```

El lab marcó "Solved". El 404 es la respuesta a `GET /404 HTTP/1.1` (path inexistente).

---

## 3. Por qué funciona

### 3.1 Anatomía del bug

Dos servidores HTTP en cadena, cada uno con su propia lógica de parseo:

```
Cliente → Front-end (proxy/CDN) → Back-end (app server)
```

El cliente manda **una sola request** TCP con headers contradictorios:

```
Content-Length: 35
Transfer-Encoding: chunked
```

RFC 7230 dice: si ambos están presentes, `Transfer-Encoding` gana y `Content-Length` debe ignorarse. Pero implementaciones reales discrepan:

| Implementación | Cuál prioriza |
|----------------|---------------|
| Apache, Nginx (front-end típico) | `Content-Length` (porque es más "tradicional") |
| Node.js, Tomcat (back-end típico) | `Transfer-Encoding` (porque siguen el RFC) |
| Algunos CDNs | Cierran la conexión si ven ambos |

Cuando frontend usa CL y backend usa TE → **CL.TE**. La inversa es **TE.CL** (raro). También hay **TE.TE** donde ambos usan TE pero uno acepta una variante obfuscada.

### 3.2 Trazado byte por byte del lab

Bytes que el cliente manda al frontend:

```
[headers]\r\n\r\n0\r\n\r\nGET /404 HTTP/1.1\r\nX-Ignore: X
                ↑ inicio del body, byte 0 del body
                                            ↑ byte 35 del body
```

**Frontend (Apache-style, lee CL=35)**:

- Lee 35 bytes de body.
- Considera la request completa.
- Forwardea TODOS los bytes (headers + 35 bytes de body) al backend en la misma conexión TCP keep-alive.

**Backend (Node-style, lee TE=chunked)**:

- Recibe los headers.
- Empieza a parsear chunked encoding del body.
- Lee `0\r\n` → chunk size 0 → "fin del body".
- Lee `\r\n` → terminator (línea vacía después del último chunk).
- **Considera la request 1 completa** después de los primeros 5 bytes del body.
- Los bytes restantes (`GET /404 HTTP/1.1\r\nX-Ignore: X`, 30 bytes) **quedan en el buffer del socket TCP**.

**Backend, response a request 1**: 200 OK normal (la home).

**Backend, espera la siguiente request en el socket**: ya tiene 30 bytes pre-buffered: `GET /404 HTTP/1.1\r\nX-Ignore: X`. Espera más bytes para completar la request.

**Cliente manda request 2** (idéntica a la primera). Frontend la forwardea al backend en la misma conexión.

**Backend, lee desde el buffer**:

```
GET /404 HTTP/1.1\r\nX-Ignore: XPOST / HTTP/1.1\r\nHost: ...\r\n\r\n0\r\n\r\nGET /404...
```

Parsea: método `GET`, path `/404`, header `X-Ignore: XPOST` (el `X` final del prefix se concatena con `POST` de la request 2 formando un valor de header), después... headers de la request 2 quedan como headers del GET smuggled.

**Backend procesa GET /404** → 404 Not Found. Esa es la respuesta que recibe el cliente como **respuesta 2**.

Pero el lab respondió 404 las **dos veces**. Por qué: el backend de PortSwigger probablemente tenía conexiones keep-alive con buffers preexistentes de tests de otros estudiantes, así que la primera request del cliente ya recibió bytes smuggled de runs previos. La diferencia con la segunda no aplica linealmente — el behavior ya estaba contaminado por uso compartido del backend.

Para el lab eso da igual: el lab valida que el backend procese `GET /404` como response (vía detection del 404 con cuerpo correcto), no que sea exclusivamente la segunda response.

### 3.3 Diferencia entre CL.TE, TE.CL, TE.TE

| Variante | Frontend lee | Backend lee | Mecánica |
|----------|--------------|-------------|----------|
| **CL.TE** | Content-Length | Transfer-Encoding | Frontend forwardea N bytes; backend consume M < N por chunked terminator; sobrantes smuggled. (Este lab.) |
| **TE.CL** | Transfer-Encoding | Content-Length | Frontend lee chunked completo; backend solo lee CL bytes; chunks pendientes quedan en socket. |
| **TE.TE** | Transfer-Encoding | Transfer-Encoding | Ambos usan TE, pero uno solo entiende una variante obfuscada (`Transfer-Encoding: chunked\r\nTransfer-Encoding: x`). El que falla cae a CL implícito. |

Cada variante requiere payload distinto. PortSwigger tiene labs separados para cada una.

### 3.4 ¿Por qué el método "differential responses" funciona como detector?

Es un canal lateral: la mera ejecución de la request smuggled no es observable directamente (el frontend solo ve la response a la POST original, no a la GET smuggled). Pero el smuggled prefix afecta el procesamiento de la **siguiente** request en el socket, y esa siguiente request sí tiene su response visible.

El truco: hacer que el smuggled prefix corrompa la siguiente request de forma que su response sea **distinguible** de la respuesta normal. `GET /404 HTTP/1.1` es perfecto: el backend la procesa como GET a un path que no existe → 404. Diferente de la home (200) o un POST (200/302). Status code es la señal más simple.

Otras técnicas de detección:

- **Timing-based** (lab `lab-confirming-cl-te-via-timing`): mandar payload donde el backend espera más bytes y el frontend ya cerró su lado → response se demora. Diferencia de tiempo es la señal.
- **Self-poisoning con headers conocidos**: mandar `GET /admin HTTP/1.1` smuggled con cookies del atacante → si admin requiere auth, ver si la siguiente request muestra error de auth distinto.

### 3.5 ¿Por qué este bug es Practitioner y no Apprentice?

Cuatro saltos sobre vulnerabilidades de aplicación clásicas:

1. **Conocimiento de HTTP a nivel de bytes**: hay que entender CRLF, chunked encoding, keep-alive sockets. No alcanza con conocer "headers y body".
2. **Operación con tooling especializado**: Burp Repeater requiere config específica (HTTP/1, no auto-CL). Curl no funciona porque maneja CL automático.
3. **Modelo mental de dos servidores**: la mayoría de los bugs web asumen un solo servidor. Smuggling requiere razonar sobre la frontera entre dos.
4. **Detección indirecta**: la víctima del gap es la siguiente request, no la propia. Requiere observación sobre dos requests distintas.

### 3.6 Defensa correcta

Las defensas son del lado del **frontend** y del **backend** simultáneamente — ninguna sola alcanza:

```nginx
# Frontend (Nginx) - rechazar requests con headers ambiguos
http {
    # No forwarding chunked si CL también está presente
    proxy_http_version 1.1;
    proxy_set_header Connection "";

    # Validar headers en el frontend, rechazar contradictorios
    if ($http_transfer_encoding != "" -and $http_content_length != "") {
        return 400;
    }
}
```

Lista de defensas:

1. **Normalizar headers en el frontend**: si hay tanto CL como TE, rechazar la request con 400. RFC permite ignorar uno, pero ignorar es la causa del bug — rechazar es más seguro.
2. **No hacer keep-alive entre frontend y backend**: cada request del frontend al backend abre una conexión nueva. Elimina el vector — bytes "smuggled" no tienen socket compartido para llegar a otra request. Costo: latencia y consumo de file descriptors.
3. **Usar HTTP/2 entre frontend y backend**: HTTP/2 binariza los bodies en frames con longitud explícita. No hay ambigüedad CL/TE. Cierra la categoría completa.
4. **Validación estricta del backend**: el backend debe rechazar (no aceptar silenciosamente) headers contradictorios o mal formados. Implementaciones modernas (Node 18+, Go net/http reciente) ya hacen esto.
5. **Mismo software de proxy/server en frontend y backend**: si ambos son la misma versión de Nginx, el parser es idéntico — no hay gap por construcción. No siempre es viable arquitectónicamente, pero elimina el desync.

---

## 4. Resumen

```mermaid
flowchart LR
    A[1. POST con CL=35 y TE=chunked]
    B[2. Frontend lee 35 bytes - forwardea todo]
    C[3. Backend lee chunked - termina en byte 5]
    D[4. 30 bytes smuggled quedan en socket TCP]
    E[5. Mandar misma request otra vez]
    F[6. Backend prepende smuggled bytes a request 2]
    G[7. Backend procesa GET /404 - retorna 404]
    H[8. Cliente ve 404 - confirmado CL.TE]

    A --> B --> C --> D --> E --> F --> G --> H
```

Tres ideas:

1. **Smuggling es un bug de frontera entre dos parsers HTTP, no un bug de aplicación**. Front-end y back-end procesan el body con reglas distintas para los mismos bytes; el gap entre las dos vistas es el canal de ataque. La aplicación en sí no tiene nada que ver — es un bug de infraestructura HTTP.
2. **El detector "differential responses" funciona porque el smuggled prefix corrompe la siguiente request en el socket, no la propia**. La response observable es la de la request 2, no de la 1. Requiere modelo mental de keep-alive sockets compartidos entre requests.
3. **HTTP/2 cierra la categoría completa** porque binariza los bodies con frames de longitud explícita, eliminando la ambigüedad CL/TE. Si el path frontend↔backend es HTTP/2, el bug no existe. La defensa por construcción es preferible a normalización defensiva en HTTP/1.

---

## 5. Contramedidas

1. **HTTP/2 entre frontend y backend**: bodies framed binariamente, sin ambigüedad CL/TE. Cierra la categoría por construcción.
2. **Rechazar headers contradictorios en el frontend**: si hay tanto `Content-Length` como `Transfer-Encoding`, devolver 400. La normalización RFC permite ignorar uno, pero ignorar es la causa del bug.
3. **Sin keep-alive entre frontend y backend**: cada request del frontend al backend abre conexión nueva. Bytes "smuggled" no encuentran socket compartido. Costo: latencia + file descriptors.
4. **Validación estricta del parser HTTP del backend**: rechazar (no aceptar silenciosamente) headers ambiguos. Node 18+, Go net/http reciente, Tomcat 10+ ya lo hacen.
5. **Same-software end-to-end**: si frontend y backend son la misma versión de Nginx, no hay gap de parsing. Restringe arquitectura pero elimina el bug.
6. **WAF con reglas específicas para CL.TE/TE.CL**: detectar combinaciones inusuales (`Transfer-Encoding: chunked\r\n`, encodings obfuscados, payloads con `0\r\n\r\n` seguido de método HTTP). Defensa-en-profundidad, no primaria.
7. **Logging y monitoring de respuestas anómalas**: requests POST que reciben 404 a paths inesperados es señal de smuggling exitoso. Alertar sobre patrones de status codes incongruentes con paths.
8. **Tests automatizados de smuggling en CI**: herramientas como [`smuggler`](https://github.com/defparam/smuggler) o Burp Smuggler pueden correr contra staging para detectar regresiones. Integrar en pipeline pre-deploy.
9. **Restringir métodos HTTP en el frontend**: si la app solo necesita GET/POST, rechazar los demás en el frontend. Reduce el universo de smuggled requests aunque no cierra el bug.
10. **Connection: close en respuestas si se detecta anomalía**: si el frontend detecta posibles bytes residuales (response truncada, length mismatch), forzar cierre de conexión. Limita el daño aunque la primera smuggle pase.

---

## 6. Referencias

- PortSwigger Web Security Academy. (s.f.). *Lab: HTTP request smuggling, confirming a CL.TE vulnerability via differential responses*. https://portswigger.net/web-security/request-smuggling/finding/lab-confirming-cl-te-via-differential-responses
- PortSwigger Web Security Academy. (s.f.). *HTTP request smuggling*. https://portswigger.net/web-security/request-smuggling
- PortSwigger Research. (2019). *HTTP Desync Attacks: Request Smuggling Reborn* (James Kettle). https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
- IETF. (2014). *RFC 7230: HTTP/1.1 Message Syntax and Routing*. https://datatracker.ietf.org/doc/html/rfc7230
- IETF. (2022). *RFC 9112: HTTP/1.1*. https://datatracker.ietf.org/doc/html/rfc9112 (obsoleta RFC 7230, mantiene la regla de TE > CL)
- OWASP Foundation. (s.f.). *HTTP Request Smuggling*. https://owasp.org/www-community/attacks/HTTP_Request_Smuggling
- MITRE Corporation. (2024). *CWE-444: Inconsistent Interpretation of HTTP Requests ('HTTP Request/Response Smuggling')*. https://cwe.mitre.org/data/definitions/444.html
- MITRE Corporation. (2024). *ATT&CK Technique T1190: Exploit Public-Facing Application*. https://attack.mitre.org/techniques/T1190/
- swisskyrepo. (s.f.). *PayloadsAllTheThings — Request Smuggling*. https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling
- defparam. (s.f.). *smuggler — HTTP Request Smuggling detection tool* [Software]. GitHub. https://github.com/defparam/smuggler
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook* (2nd ed.). Wiley. Cap. 17 (Attacking Application Architecture, sección sobre desync).
- Inventario interno: [`inventario/03-analisis-vulnerabilidades/web/analisis-request-smuggling.md`](../../../inventario/03-analisis-vulnerabilidades/web/analisis-request-smuggling.md)
