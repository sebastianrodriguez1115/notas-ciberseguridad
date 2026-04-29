# Enumeración SMB (Server Message Block)

## Descripción
SMB (Server Message Block) es un protocolo de red para compartir archivos, impresoras y otros recursos entre nodos de una red. Ampliamente usado en entornos Windows (puertos 139/tcp y 445/tcp). La enumeración SMB permite obtener información del sistema operativo, usuarios, grupos, recursos compartidos, sesiones activas, politicas de contraseñas y servicios en ejecución. Con credenciales validas (o sesion nula en versiones antiguas), la cantidad de información obtenible es muy elevada.

## Clasificación
- **Fase**: Enumeración
- **MITRE ATT&CK**: T1135 (Network Share Discovery) — shares; T1087 (Account Discovery) — usuarios; T1069 (Permission Groups Discovery) — grupos; T1007 (System Service Discovery) — servicios; T1110 (Brute Force) — fuerza bruta de credenciales
- **Plataforma**: Multi
- **Dificultad**: Básica

## Herramientas
- **nmap** (scripts NSE SMB) — enumeración sin/con credenciales vía NSE
- **smbclient** — cliente SMB para listar y acceder a recursos compartidos
- **rpcclient** — interacción con RPC de Samba/Windows (sesion nula)
- **enum4linux** — enumeración automatizada combinando múltiples herramientas
- **smbmap** — mapeado de shares con permisos y ejecución remota de comandos
- **Metasploit** — módulos para versión SMB y fuerza bruta
- **Hydra** — fuerza bruta de credenciales SMB

## Comandos / Ejemplos

### Escaneo inicial
```bash
nmap <subnet>/24                             # descubrimiento de hosts
nmap <target> -p445 -sV                      # version SMB
nmap <target> -sU --top-port 25 -sV          # escaneo UDP (NetBIOS 137)
```

### Scripts NSE de Nmap
```bash
# OS, nombre NetBIOS, dominio, FQDN
nmap <target> -p445 --script smb-os-discovery

# Dialectos SMB soportados (SMBv1 es vulnerable!)
nmap -p445 --script smb-protocols <target>

# Modo de seguridad (signing, challenge-response)
nmap -p445 --script smb-security-mode <target>

# Sesiones activas (requiere credenciales admin)
nmap -p445 --script smb-enum-sessions \
  --script-args smbusername=administrator,smbpassword=<pass> <target>

# Recursos compartidos (con y sin credenciales)
nmap -p445 --script smb-enum-shares <target>
nmap -p445 --script smb-enum-shares \
  --script-args smbusername=administrator,smbpassword=<pass> <target>

# Usuarios del sistema
nmap -p445 --script smb-enum-users \
  --script-args smbusername=administrator,smbpassword=<pass> <target>

# Dominios (politicas de contrasenas, lockout)
nmap -p445 --script smb-enum-domains \
  --script-args smbusername=administrator,smbpassword=<pass> <target>

# Grupos locales y de dominio
nmap -p445 --script smb-enum-groups \
  --script-args smbusername=administrator,smbpassword=<pass> <target>

# Servicios Windows en ejecucion
nmap -p445 --script smb-enum-services \
  --script-args smbusername=administrator,smbpassword=<pass> <target>
```

### smbclient
```bash
smbclient -L <target> -N              # listar shares (sesion nula)
smbclient //<target>/Public -N        # conectar a share anonimo
smbclient //<target>/C$ -U admin      # conectar con credenciales

# Dentro de smbclient:
# ls, cd <dir>, get <file>, put <file>, exit
```

### rpcclient (sesion nula)
```bash
rpcclient -U "" -N <target>
# Dentro de rpcclient:
# srvinfo          → info del servidor
# enumdomusers     → usuarios del dominio
# lookupnames <u>  → SID de un usuario
# enumdomgroups    → grupos del dominio
```

### enum4linux
```bash
enum4linux -o <target>   # informacion OS
enum4linux -U <target>   # usuarios
enum4linux -S <target>   # shares
enum4linux -G <target>   # grupos
enum4linux -i <target>   # impresoras
enum4linux -a <target>   # todo lo anterior
```

### smbmap
```bash
smbmap -u guest -p "" -d . -H <target>                       # como guest
smbmap -u administrator -p <pass> -d . -H <target>           # con credenciales
smbmap -u administrator -p <pass> -d . -H <target> -x "whoami"     # ejecutar comando
smbmap -u administrator -p <pass> -d . -H <target> -r "C$"   # listar directorio
smbmap -u administrator -p <pass> -d . -H <target> --download "C$\flag.txt"
smbmap -u administrator -p <pass> -d . -H <target> --upload "/ruta/local" "C$\archivo"
```

### Metasploit
```bash
use auxiliary/scanner/smb/smb_version  # detectar version
use auxiliary/scanner/smb/smb2         # verificar soporte SMB2
set RHOSTS <target>
run
```

### Fuerza bruta
```bash
# Metasploit
use auxiliary/scanner/smb/smb_login
set RHOSTS <target>
set SMBUser <usuario>
set PASS_FILE /usr/share/wordlists/metasploit/unix_passwords.txt
exploit

# Hydra
hydra -l <usuario> -P /usr/share/wordlists/rockyou.txt <target> smb
```

## Contramedidas
- Deshabilitar SMBv1 (vulnerable a EternalBlue/MS17-010)
- Habilitar SMB Signing obligatorio para prevenir ataques relay
- Deshabilitar sesiones nulas (null sessions) en el registro de Windows
- Restringir acceso SMB por firewall a IPs de administración autorizadas
- Deshabilitar el acceso de invitado (guest account) a recursos compartidos
- Monitorear eventos de Windows: 4624 (logon), 5140 (share access), 4625 (failed logon)

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1135: Network Share Discovery. https://attack.mitre.org/techniques/T1135/
