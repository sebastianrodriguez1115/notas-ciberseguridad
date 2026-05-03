---
title: Análisis de Vulnerabilidades con Nmap Scripting Engine (NSE)
slug: analisis-nmap-nse
aliases: [Análisis de Vulnerabilidades con Nmap Scripting Engine (NSE)]
fase: [Análisis de Vulnerabilidades]
plataforma: Multi
dificultad: Intermedia
mitre: [T1595.002]
related: []
learning_refs: []
---

# Análisis de Vulnerabilidades con Nmap Scripting Engine (NSE)

## Descripción
El Nmap Scripting Engine (NSE) es una de las características más potentes de Nmap, permitiendo a los usuarios escribir y compartir scripts para automatizar una amplia variedad de tareas de red. En el contexto del análisis de vulnerabilidades, NSE permite la detección proactiva de fallos de seguridad conocidos, configuraciones incorrectas y servicios vulnerables durante la fase de escaneo.

## Herramientas
- **Nmap** — Escáner de red versátil utilizado para descubrimiento de hosts y servicios.
- **Scripts NSE** — Conjunto de scripts integrados en Nmap para la detección avanzada de vulnerabilidades y configuraciones incorrectas.

## Comandos / Ejemplos
Escaneo de vulnerabilidades genérico en un objetivo:
```bash
nmap -sV --script vuln <target_ip>
```

Uso de scripts específicos para detección de vulnerabilidades SMB (ej. MS17-010):
```bash
nmap -p 445 --script smb-vuln-ms17-010 <target_ip>
```

Detección de vulnerabilidades HTTP utilizando diccionarios de SecLists para fuerza bruta:
```bash
nmap -p 80 --script http-enum --script-args http-enum.basepath=/usr/share/seclists/Discovery/Web-Content/common.txt <target_ip>
```

## Contramedidas
- Mantener los servicios y sistemas operativos actualizados.
- Deshabilitar servicios innecesarios y cerrar puertos no utilizados.
- Implementar sistemas de detección y prevención de intrusiones (IDS/IPS) para identificar escaneos NSE agresivos.
- Configurar firewalls para limitar el acceso a servicios críticos.

## Referencias
- Harper, A., et al. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook*. McGraw-Hill Education.
- Hertzog, R., & O'Gorman, J. (2017). *Kali Linux Revealed: Mastering the Penetration Testing Distribution*. OffSec Press.
