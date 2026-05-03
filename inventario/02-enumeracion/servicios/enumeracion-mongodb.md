---
title: Enumeración MongoDB (Puerto 27017)
slug: enumeracion-mongodb
aliases: [Enumeración MongoDB (Puerto 27017)]
fase: [Enumeración]
plataforma: Multi
dificultad: Básica
mitre: [T1046]
related: []
learning_refs: []
---

# Enumeración MongoDB (Puerto 27017)

## Descripción
MongoDB es una base de datos NoSQL popular basada en documentos. Una vulnerabilidad crítica recurrente es la exposición de bases de datos sin autenticación, permitiendo el acceso total a los datos. La enumeración de MongoDB se enfoca en verificar si la autenticación está habilitada, extraer información sobre bases de datos, colecciones y registros, así como identificar la versión del servidor y posibles configuraciones inseguras.

## Herramientas
- **mongo** / **mongosh** — cliente interactivo oficial de MongoDB
- **nmap** — scripts NSE (mongodb-info, mongodb-databases, mongodb-brute)
- **Metasploit** — módulos auxiliares para escaneo y fuerza bruta
- **NoSQLMap** — herramienta para automatizar ataques de inyección NoSQL y enumeración

## Comandos / Ejemplos

### Escaneo con Nmap
```bash
# Identificar versión e información básica de la base de datos
nmap -p 27017 -sV --script mongodb-info 10.10.10.10

# Listar bases de datos si no requiere autenticación
nmap -p 27017 --script mongodb-databases 10.10.10.10

# Fuerza bruta de credenciales (si la autenticación está activa)
nmap -p 27017 --script mongodb-brute --script-args userdb=users.txt,passdb=pass.txt 10.10.10.10
```

### Enumeración Manual con Mongo Shell
```bash
# Conexión sin autenticación
mongosh --host 10.10.10.10 --port 27017

# Comandos de enumeración dentro del shell
test> show dbs                          # Listar todas las bases de datos
test> use admin                         # Cambiar a la base de datos 'admin'
admin> show collections                 # Listar colecciones dentro de la BD
admin> db.getUsers()                    # Listar usuarios registrados
admin> db.system.version.find()         # Obtener versión detallada
admin> db.collection_name.find().pretty() # Mostrar contenido de una colección
```

### Fuerza bruta con Metasploit
```bash
msfconsole -q
use auxiliary/scanner/mongodb/mongodb_login
set RHOSTS 10.10.10.10
set USER_FILE /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt
set PASS_FILE /usr/share/wordlists/seclists/Passwords/Common-Credentials/top-100-common-passwords.txt
run
```

### Extracción de datos con NoSQLMap
```bash
# Automatización de la enumeración
nosqlmap --host 10.10.10.10
```

## Contramedidas
- **Habilitar autenticación** mediante el mecanismo SCRAM (Salted Challenge Response Authentication Mechanism) en `mongod.conf`.
- **Vincular el servicio a 127.0.0.1** (localhost) si el acceso remoto no es obligatorio.
- **Utilizar TLS/SSL** para cifrar todo el tráfico entre los clientes y el servidor MongoDB.
- **Implementar el Principio de Menor Privilegio** asignando roles específicos a cada usuario de la base de datos.
- **Habilitar el firewall** del sistema operativo para restringir el acceso al puerto 27017 únicamente a IPs autorizadas.

## Referencias
- MongoDB Documentation. (2024). Security Checklist. https://www.mongodb.com/docs/manual/administration/security-checklist/
- HackTricks. (2024). 27017 - Pentesting MongoDB. https://book.hacktricks.xyz/network-services-pentesting/27017-27018-pentesting-mongodb
- SecLists: /usr/share/wordlists/seclists/Passwords/Default-Credentials/mongodb-betterdefaultpasslist.txt
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
