---
title: Análisis de Vulnerabilidades: Servicios Mal Configurados
slug: analisis-servicios-mal-configurados
aliases: ["Análisis de Vulnerabilidades: Servicios Mal Configurados"]
fase: [Análisis de Vulnerabilidades]
plataforma: Multi
dificultad: Básica
mitre: [T1078]
related: []
learning_refs: []
---

# Análisis de Vulnerabilidades: Servicios Mal Configurados

## Descripción
Los servicios de red, a menudo instalados con configuraciones por defecto (Insecure Defaults), pueden exponer fallos de seguridad graves. El análisis se centra en identificar credenciales por defecto, protocolos inseguros (como FTP, Telnet o HTTP sin SSL), y funciones administrativas expuestas sin protección.

## Herramientas
- **Nmap** (NSE) — Uso de scripts de enumeración para identificar servicios vulnerables y configuraciones débiles.
- **Metasploit Framework** — Plataforma para el desarrollo y ejecución de exploits contra servicios mal configurados.
- **Hydra** — Herramienta de fuerza bruta rápida para validar credenciales por defecto en múltiples protocolos.
- **SecLists** — Colección de listas de diccionarios para pruebas de seguridad, incluyendo credenciales comunes.

## Comandos / Ejemplos
Probar credenciales por defecto en un servidor SSH utilizando `Hydra` y SecLists:
```bash
hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/default-passwords.txt <target_ip> ssh
```

Detectar configuraciones inseguras de SMB (ej. firmas deshabilitadas) con Nmap:
```bash
nmap -p 445 --script smb-security-mode.nse <target_ip>
```

Uso del módulo `auxiliary/scanner/http/http_version` de Metasploit para detectar banners reveladores:
```bash
msfconsole -q -x "use auxiliary/scanner/http/http_version; set RHOSTS <target_ip>; run"
```

Verificar la exposición del panel de administración de Tomcat (credenciales comunes):
```bash
nmap -p 8080 --script http-tomcat-brute --script-args userdb=users.txt,passdb=pass.txt <target_ip>
```

## Contramedidas
- Cambiar todas las contraseñas por defecto inmediatamente tras la instalación.
- Deshabilitar protocolos obsoletos e inseguros (TLS 1.0/1.1, SSL v3).
- Implementar el endurecimiento (Hardening) de servicios basado en guías como CIS Benchmarks.
- Utilizar autenticación multifactor (MFA) para todas las interfaces administrativas.

## Referencias
- Harper, A., et al. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook*. McGraw-Hill Education.
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
