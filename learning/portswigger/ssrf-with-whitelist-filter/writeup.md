# Writeup: SSRF with whitelist-based input filter (PortSwigger)

- **Lab**: SSRF with whitelist-based input filter
- **URL**: https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter
- **Categoría**: SSRF + bypass de whitelist por **parser differential sobre componente host de URL**
- **Dificultad**: Practitioner
- **Credenciales**: no requiere login

---

## 1. Objetivo

Mismo target final (panel admin en loopback, borrar `carlos`) que los labs SSRF anteriores, pero ahora el filtro sobre `stockApi` es una **whitelist estricta del dominio del microservicio de stock** (`stock.weliketoshop.net` en este lab; el nombre exacto puede variar entre instancias). No hay open redirect en el dominio confiable que componer (lab #4); las representaciones alternativas de loopback no aplican porque la whitelist no enumera lo malo, exige lo bueno.

El bypass ataca **inconsistencias entre dos URL parsers** que ven la misma string: el del filtro y el del cliente HTTP que ejecuta la petición. Los dos parsers tratan distinto un `%23` (que es `#` URL-encodeado), lo que permite que vean **hosts distintos** en la misma URL.

### El insight central

Una whitelist parseada incorrectamente es tan rota como una blacklist. La fortaleza nominal de una whitelist depende de que el parser que valida y el parser que ejecuta acuerden exactamente qué es el host. Cuando difieren, la whitelist se aplica sobre una representación lógica que no es la que se va a conectar.

Es la misma clase de bug del lab #3 (double encoding sobre el **path** `admin` → `%2561dmin`), pero ahora aplicada al componente **host/userinfo** de la URL. Misma idea, distinto componente.

---

## 2. Reconocimiento

### 2.1 Confirmar que el filtro es whitelist estricta

Capturar la POST `/product/stock` y mandar a Repeater. El primer test que revela cómo es el filtro:

```
stockApi=http://localhost/admin
```

Respuesta:
```
HTTP/2 400 Bad Request
"External stock check host must be stock.weliketoshop.net"
```

Dos cosas importantes:
- El error es **explícito**: dice qué host espera. Esto es importante para el ataque (sabemos el target de la whitelist) y didácticamente útil. En sistemas reales el error suele ser genérico.
- El filtro hace **parsing real de URL**, no substring matching. Sabe que `host=localhost` y compara con el esperado. Esto descarta bypasses naive donde simplemente meter el dominio confiable como substring.

### 2.2 Cuando me equivoqué de dominio

Empecé asumiendo que el dominio confiable era `stock.weliveshecurity.net` (heredado mentalmente de labs anteriores). El error 400 del lab me dio el dominio real (`stock.weliketoshop.net`) inmediatamente. Lección operacional: cuando el server devuelve un error verboso, leerlo enterito antes de iterar; ahorra ciclos. PortSwigger pone esos hints intencionalmente.

---

## 3. Resolución

### 3.1 Intento 1: userinfo simple con `@`

Idea naive: meter el dominio confiable en posición de userinfo, `localhost` como host real.

```
stockApi=http://[email protected]/admin
```

Respuesta:
```
HTTP/2 400 "External stock check host must be stock.weliketoshop.net"
```

Falla porque el filtro parsea URL correctamente per RFC 3986: ve `userinfo=stock.weliketoshop.net`, `host=localhost`. La whitelist se aplica sobre `host` parseado, no sobre la string. Naive no alcanza.

(Esto sí funcionaría contra filtros basados en regex/substring `if "stock.weliketoshop.net" in url: pass`. Vale la pena probarlo siempre primero, es una línea, y descarta toda una clase de filtros con dos requests.)

### 3.2 Intento 2: dirección equivocada

Probé `stock.weliketoshop.net%[email protected]/admin` (dominio confiable adelante con `%23`, localhost después del `@`). El filtro parsea esta URL y ve `userinfo=stock.weliketoshop.net%23`, `host=localhost` → rechaza. La dirección importa: el `%23` tiene que estar en el componente que el filtro aceptará como host parseado, **no** en el componente que va a ser el host real.

### 3.3 Intento 3: encoding simple del `#`

Dirección correcta (localhost adelante, dominio confiable detrás del `@`), pero con `%23` simple en vez de `%2523`:

```
stockApi=http://localhost:80%[email protected]/admin
```

Respuesta:
```
HTTP/2 400 "External stock check host must be stock.weliketoshop.net"
```

Falla porque el form parser decodea ese `%23` y lo entrega al filtro como `#` literal: `http://localhost:80#@stock.weliketoshop.net/admin`. El filtro al parsear URL ve `#` como fragment delimiter, splitea la URL en `host=localhost`, `fragment=@stock.weliketoshop.net/admin`. Whitelist se aplica sobre `localhost`, rechaza.

### 3.4 Payload final: doble encoding del `#`

```
stockApi=http://localhost:80%[email protected]/admin
```

`%2523` decodea una vez a `%23` (literal en la string, todavía encodeado). El form parser entrega al filtro: `http://localhost:80%[email protected]/admin`.

El filtro parsea esto como URL. Crítico: los URL parsers RFC 3986 **no decodean `%XX` durante el parsing del componente**. `%23` queda literal en el userinfo. Entonces el parser del filtro ve:
- `authority = localhost:80%23@stock.weliketoshop.net`
- Splittea por `@` (separador userinfo/host)
- `userinfo = localhost:80%23`
- `host = stock.weliketoshop.net`

Whitelist compara `host == stock.weliketoshop.net` → match, **pasa**.

El filtro entrega la URL al cliente HTTP, que cuando va a abrir la conexión decodea el userinfo otra vez (comportamiento estándar para HTTP basic auth). `%23` se vuelve `#`. Re-procesa la URL conceptualmente como `http://localhost:80#@stock.weliketoshop.net/admin`. Ahora `#` es fragment delimiter, splittea distinto:
- `host = localhost`
- `port = 80`
- `path = /` (vacío, antes del `#`)
- `fragment = @stock.weliketoshop.net/admin`

Pero el path real que llega al servicio interno es `/admin` (el cliente puede mantener el path original al armar el request, o reconstruir; dependiendo de la implementación, alguna combinación de estos comportamientos lleva la petición a `localhost:80/admin`).

El bypass vive en el **gap entre quién decodea cuántas veces**:

| Componente | Pasadas de decode sobre el `%23` | Qué ve | Decisión |
|---|---|---|---|
| Form parser | 1 (form-urlencoded → texto) | `%23` literal | entrega valor al filtro |
| Filtro de whitelist | 0 (URL parser preserva `%XX`) | `%23` en userinfo | host = stock.weliketoshop.net → pasa |
| HTTP client (basic auth handling) | 1 más | `#` real | host = localhost → ataque |

Total: el filtro hace 1 decode (form), el cliente HTTP hace 2 (form + userinfo basic-auth). El target final no es el que la whitelist validó.

### 3.5 Petición final

Para borrar carlos:

```
stockApi=http://localhost:80%[email protected]/admin/delete?username=carlos
```

Respuesta:
```
HTTP/2 302 Found
Location: /admin
```

Lab solved.

---

## 4. Errores comunes (vividos durante este lab)

Estos tres errores son didácticos. Los tres pasaron en orden cuando intenté resolver el lab.

### 4.1 Asumir el dominio de la whitelist sin leer el error

Empecé con `stock.weliveshecurity.net` (del shop ficticio de labs anteriores). El lab usaba `stock.weliketoshop.net`. El error 400 lo decía explícitamente; sólo había que leerlo. **Lección**: cuando un lab te da un mensaje de error verboso, es un hint, no un bug accidental. Leer antes de iterar.

### 4.2 Invertir la dirección de `%2523` y `@`

Había puesto el dominio confiable adelante (con `%23` después) y `localhost` después del `@`. El parser del filtro lo lee como `userinfo=dominio_confiable%23`, `host=localhost`, rechaza.

**Lección**: la posición de cada componente importa. La regla mental es:
- *Después* del `@` va lo que el filtro va a leer como `host` (debe ser el dominio confiable).
- *Antes* del `@` va lo que el cliente va a interpretar como host real una vez que decodea `%23` → `#` (debe ser `localhost` o la IP real).

Pensarlo "al revés": el atacante quiere engañar al filtro y al cliente; el filtro lee primero, así que el dominio confiable va donde el filtro va a buscar el host (después del `@`); el cliente lee segundo y "descubre" un nuevo host antes del `#`, por eso `localhost` va antes del `%2523`.

### 4.3 Usar `%23` en vez de `%2523`

Encoding simple → el form parser lo decodea a `#` y el filtro ve un fragment delimiter literal, parsea distinto, rechaza. Hay que mantener un nivel extra de encoding (`%2523`) para que sobreviva el form parser y llegue al filtro **todavía como `%23`** (texto literal, no fragment).

**Lección**: contar las pasadas de decodificación es la disciplina que evita este error. Si la doble decodificación es necesaria para el bypass, hay que mandar 2 capas de encoding sobre el carácter target. Si el form transport no decodea, 1 capa alcanza.

---

## 5. Por qué funciona (en una capa más profunda)

### 5.1 Whitelists rotas por parser differential

La defensa por whitelist es teóricamente más robusta que la defensa por blacklist, pero asume que el parser es consistente. Cuando dos parsers en el mismo pipeline ven hosts distintos en la misma URL, la whitelist se aplica sobre una representación lógica que no es la que se va a conectar. La validación se vuelve teatro.

Variantes de la misma idea aplicadas a otros componentes de URL:

- **Path**: lab #3 (`%2561dmin` → `%61dmin` → `admin`). Filtro decodea una vez, cliente decodea otra vez.
- **Host**: este lab (`%2523` confunde el parser de userinfo).
- **Scheme**: filtros que aceptan `http`/`https` pero parsean mal `\\evil.com` o `javascript:`.
- **Query/Fragment**: bypasses de filtros anti-XSS donde el parser de filtro y el parser del navegador difieren.

La generalización: **cualquier sistema con check-y-act donde los dos parsers no coinciden en normalización tiene clase de bug latente**.

### 5.2 La fix raíz es canonicalizar antes de validar

Validación correcta para un campo URL controlado por usuario:

1. **Parsear con un parser estricto** (rechazar URLs malformadas o con sintaxis ambigua).
2. **Canonicalizar**: aplicar `URI.normalize()` u operación equivalente que decodea `%XX` donde sea seguro hacerlo, normaliza case del scheme/host, resuelve `..`/`.`, deja la URL en forma única.
3. **Validar la URL canonicalizada** contra la whitelist.
4. **Resolver DNS y validar la IP final** post-resolución (no sólo el host textual). Esto previene DNS rebinding (hostname público que después resuelve a interno).
5. **Conectar usando la IP resuelta** y el host textual canonicalizado, no la URL original. Eso elimina cualquier posibilidad de que el cliente HTTP "redescubra" un host distinto al que validamos.

La invariante: el componente que valida y el componente que conecta deben usar la misma representación canónica del host. Si no, parser differential.

### 5.3 Por qué `%23` en userinfo decodea distinto al `%23` en path

Los URL parsers tratan los componentes de URL con reglas distintas. RFC 3986 define qué caracteres son válidos en cada componente y cómo se decodean. Algunos puntos relevantes:

- `userinfo` permite `pct-encoded` y un set específico de caracteres unreserved + sub-delims. `%23` (encoded `#`) es válido literalmente en userinfo.
- `host` no permite `#` literal (rompe el parsing).
- `path` permite `pct-encoded` también, pero los parsers a veces lo decodean antes de aplicar lógica de matching (porque el path se va a usar para buscar archivos/rutas, no como identificador opaco).

Cuando el cliente HTTP procesa la URL para abrir la conexión, en algunos libs *decodea* el userinfo (porque va a usarlo para basic auth, donde necesita los caracteres reales), mientras que el filtro lo trataba como texto opaco. Ese asymmetric-decode es la oportunidad del ataque.

### 5.4 Diferencia con los labs SSRF anteriores

| Lab | Filtro | Bypass | Componente atacado |
|---|---|---|---|
| #1 (loopback) | Ninguno | N/A | N/A |
| #2 (back-end discovery) | Ninguno, target a descubrir | Sweep del rango | N/A |
| #3 (blacklist) | Strings prohibidos en host y path | Representación alternativa de host (`127.1`) + double encoding del path (`%2561dmin`) | Host (representación) + Path (parser differential) |
| #4 (open redirect chain) | Allowlist same-origin | Composición con open redirect | Comportamiento del cliente HTTP (follow redirects) |
| **#5 (este, whitelist)** | **Whitelist parseada** | **Parser differential sobre host/userinfo** (`%2523`) | **Host (parser differential)** |

La progresión enseña que cada clase de filtro tiene su clase de bypass. Reconocer la clase del filtro al primer intento es la diferencia entre resolver el lab en 2 minutos o en 20.

---

## 6. Resumen de la cadena

```mermaid
flowchart TB
    A[1. Atacante envia POST /product/stock con stockApi=http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos]
    B[2. Form parser decodea una vez: stockApi value = http://localhost:80%23@stock.weliketoshop.net/admin/delete?username=carlos]
    C[3. Filtro de whitelist: URL parser ve authority = localhost:80%23@stock.weliketoshop.net, splittea por @, userinfo=localhost:80%23, host=stock.weliketoshop.net]
    D[4. Whitelist compara host == stock.weliketoshop.net, match, PASA]
    E[5. HTTP client recibe la URL, decodea userinfo para basic auth: %23 se vuelve #]
    F[6. Re-procesa URL conceptualmente como http://localhost:80#@stock.weliketoshop.net/admin/delete?username=carlos, # es fragment delimiter]
    G[7. Conecta a localhost:80, hace GET /admin/delete?username=carlos]
    H[8. Panel admin acepta sin auth en loopback, ejecuta delete]
    I[9. 302 a /admin, lab solved]

    A --> B --> C --> D --> E --> F --> G --> H --> I
```

Tres ideas para llevarse:

1. **Whitelists son tan rotas como blacklists cuando hay parser differential**. La solidez nominal de "enumerar lo bueno" depende de que el componente que valida y el componente que ejecuta vean lo mismo. Cuando difieren, la whitelist es teatro.
2. **Las clases de bypass se generalizan a través de los componentes URL**. Double encoding sobre path (lab #3) y double encoding sobre userinfo (este lab) son la misma idea aplicada a distintas partes de la URL. Aprender la clase, no el truco.
3. **Canonicalizar antes de validar es la fix raíz**, no agregar reglas a la blacklist o a la whitelist. La canonicalización elimina las representaciones alternativas y las inconsistencias entre parsers.

---

## 7. Contramedidas

En orden de robustez:

1. **No aceptar URLs del cliente para llamadas server-side**. Misma fix raíz que todos los labs SSRF: si `stockApi` viene del config server-side, la whitelist no es necesaria porque no hay input que validar.
2. **Si la URL viene del cliente, canonicalizar y luego validar**. Pseudo-código:
   ```python
   from urllib.parse import urlparse, urlunparse
   parsed = urlparse(stock_api)
   if not parsed.scheme in ('http', 'https'):
       reject()
   if parsed.hostname != ALLOWED_HOST:  # parsed.hostname descarta userinfo
       reject()
   if parsed.username or parsed.password:
       reject()  # ningún caso legítimo de userinfo en este flujo
   if parsed.fragment:
       reject()  # fragments no se mandan al servidor por HTTP, son cliente-side
   # Sólo después: usar el URL parseado y reconstruido, no el original
   safe_url = urlunparse((parsed.scheme, parsed.hostname, parsed.path, '', parsed.query, ''))
   ```
   Rechazar userinfo y fragments cierra la clase entera de bypasses por componentes URL "exóticos".
3. **Resolver DNS y validar IP final**. Aunque el host textual sea `stock.weliketoshop.net`, si resuelve a una IP en RFC 1918 o loopback (DNS rebinding), rechazar. Usar la IP resuelta para conectar.
4. **Disable follow-redirects en el cliente HTTP server-side**. Si la feature no necesita seguir redirects, `allow_redirects=False` cierra la clase de bypass del lab #4 (open redirect chain).
5. **Egress filtering**. Bloquear desde el back-end del lab cualquier conexión saliente a loopback/RFC1918/link-local. Defense in depth.
6. **Auth obligatoria en el panel admin**. La asunción "loopback ⇒ confiable" del panel admin es el bug subyacente que SSRF explota. Auth siempre, sin importar el origen aparente del request.

---

## 8. Referencias

- PortSwigger Web Security Academy. (s.f.). *Lab: SSRF with whitelist-based input filter*. https://portswigger.net/web-security/ssrf/lab-ssrf-with-whitelist-filter
- PortSwigger Web Security Academy. (s.f.). *Server-side request forgery (SSRF)*. https://portswigger.net/web-security/ssrf
- OWASP Foundation. (s.f.). *Server Side Request Forgery Prevention Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- IETF. (2005). *RFC 3986: Uniform Resource Identifier (URI): Generic Syntax*. https://www.rfc-editor.org/rfc/rfc3986
- MITRE Corporation. (2024). *CWE-918: Server-Side Request Forgery (SSRF)*. https://cwe.mitre.org/data/definitions/918.html
- MITRE Corporation. (2024). *CWE-707: Improper Neutralization*. https://cwe.mitre.org/data/definitions/707.html
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook* (2nd ed.). Wiley. Cap. 11 (Attacking Application Logic).
- Orange Tsai. (2017). *A New Era of SSRF: Exploiting URL Parsers in Trending Programming Languages*. Black Hat USA. https://www.blackhat.com/docs/us-17/thursday/us-17-Tsai-A-New-Era-Of-SSRF-Exploiting-URL-Parser-In-Trending-Programming-Languages.pdf — referencia clásica sobre parser differentials en URL parsers de stdlibs.
- Writeups hermanos:
  - [`learning/portswigger/basic-ssrf-against-localhost/writeup.md`](../basic-ssrf-against-localhost/writeup.md) — SSRF a loopback sin filtros (lab #1).
  - [`learning/portswigger/basic-ssrf-against-backend-system/writeup.md`](../basic-ssrf-against-backend-system/writeup.md) — SSRF con discovery por fuzzing (lab #2).
  - [`learning/portswigger/ssrf-with-blacklist-filter/writeup.md`](../ssrf-with-blacklist-filter/writeup.md) — SSRF + bypass de blacklist con double encoding sobre path (lab #3).
  - [`learning/portswigger/ssrf-filter-bypass-via-open-redirection/writeup.md`](../ssrf-filter-bypass-via-open-redirection/writeup.md) — SSRF + composición con open redirect (lab #4).
- Inventario interno: [`inventario/03-analisis-vulnerabilidades/web/analisis-ssrf.md`](../../../inventario/03-analisis-vulnerabilidades/web/analisis-ssrf.md)
