---
title: Análisis de Vulnerabilidades: Permisos Inseguros en Linux
slug: analisis-permisos-linux
aliases: ["Análisis de Vulnerabilidades: Permisos Inseguros en Linux"]
fase: [Análisis de Vulnerabilidades]
plataforma: Linux
dificultad: Intermedia
mitre: [T1068]
related: []
learning_refs: []
---

# Análisis de Vulnerabilidades: Permisos Inseguros en Linux

## Descripción
El análisis de permisos en sistemas Linux se centra en identificar configuraciones incorrectas que podrían permitir una escalada de privilegios (Privilege Escalation). Esto incluye archivos con permisos de escritura para todos (world-writable), binarios con bits SUID/SGID configurados incorrectamente, y capacidades (capabilities) excesivas asignadas a procesos de usuario.

## Herramientas
- **find** — Utilidad de búsqueda de archivos para identificar binarios con permisos especiales (SUID/SGID).
- **LinPEAS** — Script automatizado para la enumeración de vectores de escalada de privilegios en Linux.
- **LSE** (Linux Smart Enumeration) — Herramienta de enumeración que clasifica los hallazgos según su relevancia para la explotación.
- **getcap** — Comando para visualizar las capacidades (capabilities) asignadas a los ejecutables.

## Comandos / Ejemplos
Buscar archivos con el bit SUID configurado:
```bash
find / -perm -4000 -type f 2>/dev/null
```

Buscar directorios con permisos de escritura para cualquier usuario:
```bash
find / -perm -o+w -type d 2>/dev/null
```

Listar capacidades de binarios en el sistema:
```bash
getcap -r / 2>/dev/null
```

Ejecutar LinPEAS para un análisis automatizado completo:
```bash
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

## Contramedidas
- Aplicar el Principio de Privilegios Mínimos (PoLP).
- Auditar regularmente los binarios SUID/SGID.
- Utilizar herramientas de auditoría como `Lynis`.
- Restringir el acceso a binarios sensibles utilizando grupos y permisos específicos.

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- OccupyTheWeb (2018). *Linux Basics for Hackers*. No Starch Press.
- Hertzog, R., & O'Gorman, J. (2017). *Kali Linux Revealed: Mastering the Penetration Testing Distribution*. OffSec Press.
