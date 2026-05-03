---
title: "Sistemas: Arquitectura de Windows y Active Directory"
slug: windows-arquitectura-ad
aliases: ["Sistemas: Arquitectura de Windows y Active Directory", Active Directory, AD architecture, Windows architecture, AD pentest]
fase: [Fundamentos]
plataforma: Windows
dificultad: Básica
mitre: []
related: [enumeracion-ldap, enumeracion-kerberos, enumeracion-smb, bloodhound, pass-the-hash, credential-dumping, golden-ticket, silver-ticket]
learning_refs: []
---

# Sistemas: Arquitectura de Windows y Active Directory

## Descripción
Windows es el sistema operativo predominante en estaciones de trabajo y entornos corporativos. Comprender su arquitectura interna (Kernel vs User mode), sus procesos críticos y la estructura jerárquica de Active Directory (AD) es esencial para realizar pruebas de penetración eficaces, especialmente en las fases de post-explotación y movimiento lateral.

## Procesos Críticos de Windows

| Proceso | Descripción | Relevancia en Pentest |
| :--- | :--- | :--- |
| `System` (PID 4) | El proceso que corre el kernel de Windows. | Acceso total al hardware. |
| `smss.exe` | Session Manager Subsystem. | Gestiona las sesiones de usuario. |
| `wininit.exe` | Windows Initialization Process. | Inicia procesos críticos como `lsass.exe`. |
| `lsass.exe` | Local Security Authority Subsystem. | Gestiona la autenticación. Objetivo principal para volcar hashes (Mimikatz). |
| `services.exe` | Service Control Manager. | Inicia y gestiona los servicios del sistema. |
| `svchost.exe` | Service Host. | Contenedor para múltiples servicios que corren desde DLLs. |
| `explorer.exe` | Windows Explorer. | El entorno gráfico del usuario. |

## Fundamentos de Active Directory (AD)

Active Directory es el servicio de directorio de Microsoft que gestiona recursos (usuarios, grupos, computadoras) en una red corporativa de forma centralizada.

### Jerarquía
- **Objetos**: Entidades individuales (usuario, impresora).
- **Unidades Organizativas (OU)**: Contenedores para organizar objetos y aplicar GPOs.
- **Dominios**: El límite administrativo principal.
- **Árboles y Bosques**: Colecciones de dominios que comparten un esquema y configuración global.

### Mecanismos de Autenticación
- **NTLM (NT LAN Manager)**: Protocolo de desafío-respuesta (vulnerable a Pass-the-Hash).
- **Kerberos**: Protocolo basado en tickets (TGT/TGS) mediante un Key Distribution Center (KDC). Es el estándar moderno.

## Comandos Esenciales de Gestión (PowerShell / CMD)

### Ver información del sistema y usuarios
```powershell
systeminfo              # Resumen del sistema y parches instalados
whoami /all             # Ver privilegios y grupos del usuario actual
net user /domain        # Listar usuarios del dominio (requiere sesión AD)
```

### Gestión de Servicios y Procesos
```powershell
tasklist /v             # Listar procesos con detalle del usuario
Get-Service | Where-Object {$_.Status -eq "Running"} # Listar servicios activos (PS)
sc query state=all      # Consultar estado de todos los servicios (CMD)
```

### Navegación por el Registro
```powershell
# Consultar una clave del registro (ej. configuración de WinRM)
reg query "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System"
```

## Referencias
- Russinovich, M., Solomon, D., & Ionescu, A. (2017). *Windows Internals* (7th ed.). Microsoft Press.
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
