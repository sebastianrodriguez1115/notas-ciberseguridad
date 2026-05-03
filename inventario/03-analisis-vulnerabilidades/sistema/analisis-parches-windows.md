---
title: Análisis de Vulnerabilidades: Gestión de Parches en Windows
slug: analisis-parches-windows
aliases: ["Análisis de Vulnerabilidades: Gestión de Parches en Windows"]
fase: [Análisis de Vulnerabilidades]
plataforma: Windows
dificultad: Básica
mitre: [T1068]
related: []
learning_refs: []
---

# Análisis de Vulnerabilidades: Gestión de Parches en Windows

## Descripción
El análisis de parches en Windows consiste en identificar actualizaciones de seguridad ausentes (KBs) que podrían ser explotadas por atacantes. Una gestión de parches ineficiente es una de las principales causas de ataques exitosos de Ransomware y escalada de privilegios en entornos corporativos.

## Herramientas
- **systeminfo** — Herramienta nativa de Windows para mostrar información detallada de la configuración del sistema y parches.
- **WinPEAS** — Script de enumeración local para identificar rutas de escalada de privilegios en Windows.
- **WMI** — Infraestructura de gestión de Windows para consultar información sobre el sistema y software instalado.
- **MBSA** — Herramienta de Microsoft para identificar configuraciones de seguridad inseguras y actualizaciones faltantes.

## Comandos / Ejemplos
Listar parches instalados con `systeminfo`:
```cmd
systeminfo | findstr /B "Hotfix"
```

Buscar parches específicos mediante WMI:
```powershell
get-wmiobject -class "win32_quickfixengineering"
```

Usar `Wesng` (Windows Exploit Suggester - Next Generation) para identificar parches faltantes:
1. Generar salida de systeminfo: `systeminfo > sysinfo.txt`
2. Ejecutar Wesng: `python3 wes.py sysinfo.txt`

Ejecutar WinPEAS para un análisis de parches y vulnerabilidades locales:
```cmd
winpeas.exe
```

## Contramedidas
- Implementar un sistema de gestión de actualizaciones centralizado como WSUS (Windows Server Update Services) o SCCM.
- Habilitar actualizaciones automáticas en equipos cliente.
- Establecer una política de parcheo crítica (ej. dentro de las 48-72 horas de su publicación).
- Realizar escaneos de cumplimiento de parches mensualmente.

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Kim, P. (2018). *The Hacker Playbook 3: Practical Guide To Penetration Testing*. Secure Planet, LLC.
- Easttom, C. (2016). *Computer Security Fundamentals*. Pearson IT Certification.
