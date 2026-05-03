---
title: Enumeración RDP (Remote Desktop Protocol)
slug: enumeracion-rdp
aliases: [Enumeración RDP (Remote Desktop Protocol)]
fase: [Enumeración]
plataforma: Windows
dificultad: Básica
mitre: [T1021.001]
related: []
learning_refs: []
---

# Enumeración RDP (Remote Desktop Protocol)

## Descripción
RDP (Remote Desktop Protocol) es el protocolo propietario de Microsoft para acceso remoto gráfico a sistemas Windows. Opera en el puerto 3389/tcp por defecto, aunque administradores suelen moverlo a puertos no estándar como medida de seguridad por oscuridad. La enumeración RDP incluye: confirmar que un puerto habla el protocolo RDP, identificar la versión de Windows del objetivo y verificar si requiere NLA (Network Level Authentication). NLA restringe el acceso a usuarios autenticados antes de establecer la sesion completa, reduciendo la superficie de ataque.

## Herramientas
- **nmap** (`-A`) — escaneo agresivo para detectar RDP y caracteristicas del sistema
- **Metasploit** (`auxiliary/scanner/rdp/rdp_scanner`) — confirmar RDP y versión de Windows

## Comandos / Ejemplos

```bash
# Escaneo agresivo para detectar todos los servicios (incluye RDP en puerto no estandar)
nmap -A 10.4.21.67
# Resultado en contexto RDP:
# 3333/tcp open  ssl/dec-notes? (RDP en puerto no estandar)
# CN del certificado SSL: WIN-OMCNBKR66MN  ← hostname Windows
# OS detectado: Windows Server 2008 R2 - 2012
# Puertos RPC: 135/tcp, 49152-49175/tcp
# SMB: 139/tcp, 445/tcp

# Escaneo especifico en puerto RDP estandar
nmap -sV -p 3389 --script rdp-enum-encryption TARGET

# Confirmar RDP con Metasploit y detectar NLA
use auxiliary/scanner/rdp/rdp_scanner
set rhosts 10.4.21.67
set rport 3333          # puerto donde se sospecha que esta RDP
run
# Resultado: "Detected RDP on 10.4.21.67:3333 (Windows version: 6.3.9600) (Requires NLA: Yes)"

# Windows version mapping:
# 6.0 → Windows Vista / Server 2008
# 6.1 → Windows 7 / Server 2008 R2
# 6.2 → Windows 8 / Server 2012
# 6.3 → Windows 8.1 / Server 2012 R2
# 10.0 → Windows 10 / Server 2016/2019
```

**Detección de NLA:**
- `Requires NLA: Yes` → necesita credenciales antes de ver pantalla de login (mas seguro)
- `Requires NLA: No` → pantalla de login visible sin credenciales (vulnerable a ataques como BlueKeep en versiones antiguas)

**Vulnerabilidades RDP conocidas:**
| CVE | Afecta | Descripción |
|-----|--------|-------------|
| CVE-2019-0708 (BlueKeep) | Windows 7, Server 2008 sin parche | RCE pre-autenticación, sin NLA |
| CVE-2019-1181/1182 (DejaBlue) | Windows 8/10, Server 2012/2019 | RCE pre-autenticación |
| CVE-2020-0609/0610 | Windows RD Gateway | RCE sin autenticación |

## Contramedidas
- Habilitar NLA (Network Level Authentication) obligatoriamente
- Mantener sistemas Windows actualizados (parches para BlueKeep, DejaBlue)
- Restringir el acceso RDP por firewall a IPs de administración autorizadas
- Usar una VPN antes de permitir conexiones RDP desde internet
- Implementar MFA para autenticación RDP
- Monitorear Event ID 4625 (logon fallido) y 4624 (logon exitoso) en Windows Event Log

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1021.001: Remote Services: Remote Desktop Protocol. https://attack.mitre.org/techniques/T1021/001/
