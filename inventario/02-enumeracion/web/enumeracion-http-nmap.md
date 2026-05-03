---
title: Enumeración HTTP con Scripts NSE de Nmap
slug: enumeracion-http-nmap
aliases: [Enumeración HTTP con Scripts NSE de Nmap]
fase: [Enumeración]
plataforma: Web
dificultad: Básica
mitre: [T1046]
related: []
learning_refs: []
---

# Enumeración HTTP con Scripts NSE de Nmap

## Descripción
Uso de scripts NSE (Nmap Scripting Engine) especificos para HTTP que permiten enumerar rutas y directorios conocidos, inspeccionar cabeceras de respuesta, identificar métodos HTTP permitidos y detectar la presencia de WebDAV en servidores web (IIS, Apache, nginx). Mas silencioso que Nikto pero menos exhaustivo. Ideal como paso inicial de enumeración web antes de herramientas mas ruidosas.

## Herramientas
- **nmap** — escaner de red con motor de scripts NSE
  - `http-enum` — enumera directorios y rutas conocidas en el servidor
  - `http-headers` — extrae cabeceras HTTP de la respuesta del servidor
  - `http-webdav-scan` — detecta y enumera WebDAV
  - `http-methods` — lista los métodos HTTP permitidos (GET, POST, PUT, DELETE, etc.)

## Comandos / Ejemplos

```bash
# Enumeracion de directorios y rutas conocidas (similar a nikto, mas silencioso)
nmap -sV -p 80 --script http-enum 10.4.31.227

# Inspeccion de cabeceras HTTP de respuesta
nmap -sV -p 80 --script http-headers 10.4.31.227

# Deteccion y enumeracion de WebDAV
nmap -sV -p 80 --script http-webdav-scan \
  --script-args http-methods.url-path=/webdav/ 10.4.17.80

# Escaneo agresivo con multiples scripts HTTP
nmap -A 10.4.17.80
nmap -A 10.4.17.80 -p80 --script=http-enum

# Metodos HTTP permitidos
nmap -p 80 --script http-methods --script-args http-methods.url-path=/webdav/ TARGET

# Combinar multiples scripts NSE
nmap -p 80,443 --script "http-enum,http-headers,http-methods" TARGET
```

**Resultados esperados de http-enum:**
```
PORT   STATE SERVICE
80/tcp open  http
| http-enum:
|   /admin/: Possible admin folder
|   /login.php: Possible admin folder
|   /robots.txt: Robots file
```

**Resultados esperados de http-headers:**
```
| http-headers:
|   Server: Apache/2.4.29 (Ubuntu)
|   X-Powered-By: PHP/7.2.10
|   Content-Type: text/html; charset=UTF-8
```

## Contramedidas
- Eliminar o restringir el acceso a rutas administrativas con autenticación
- Ocultar cabeceras de versión del servidor (`ServerTokens Prod` en Apache, `server_tokens off` en nginx)
- Deshabilitar métodos HTTP innecesarios (PUT, DELETE, TRACE) en la configuración del servidor
- Deshabilitar WebDAV si no se necesita
- Monitorear logs de acceso para detectar escaneos NSE (múltiples peticiones a rutas conocidas)

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1046: Network Service Discovery. https://attack.mitre.org/techniques/T1046/
