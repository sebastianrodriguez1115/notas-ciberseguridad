---
title: Enumeración Elasticsearch (Puerto 9200)
slug: enumeracion-elasticsearch
aliases: [Enumeración Elasticsearch (Puerto 9200)]
fase: [Enumeración]
plataforma: Multi
dificultad: Básica
mitre: [T1046]
related: []
learning_refs: []
---

# Enumeración Elasticsearch (Puerto 9200)

## Descripción
Elasticsearch es un motor de búsqueda y analítica distribuido basado en JSON. Las instancias de Elasticsearch a menudo se configuran sin autenticación por defecto en versiones antiguas o en configuraciones erróneas, permitiendo el acceso total a los datos almacenados. La enumeración de Elasticsearch se centra en identificar la versión, listar índices y nodos, y extraer documentos sensibles mediante la API REST.

## Herramientas
- **curl** — para interactuar directamente con la API REST
- **jq** — para procesar y leer las respuestas JSON de Elasticsearch
- **nmap** — scripts NSE (elasticsearch-info, elasticsearch-brute)
- **Metasploit** — módulos auxiliares para escaneo y extracción de datos

## Comandos / Ejemplos

### Escaneo con Nmap
```bash
# Identificar versión e información del cluster
nmap -p 9200 -sV --script elasticsearch-info 10.10.10.10
```

### Enumeración Manual con Curl (API REST)
```bash
# Obtener información básica del cluster y versión
curl -s http://10.10.10.10:9200 | jq .

# Listar todos los índices (bases de datos)
curl -s http://10.10.10.10:9200/_cat/indices?v

# Listar nodos del cluster
curl -s http://10.10.10.10:9200/_cat/nodes?v

# Buscar datos en un índice específico
curl -s http://10.10.10.10:9200/<index_name>/_search?q=*&pretty

# Listar plugins instalados
curl -s http://10.10.10.10:9200/_cat/plugins?v
```

### Enumeración de Nodos y Configuración
```bash
# Ver configuración detallada de los nodos
curl -s http://10.10.10.10:9200/_nodes | jq .
```

### Fuerza bruta con Metasploit (Si tiene autenticación)
```bash
msfconsole -q
use auxiliary/scanner/http/elasticsearch_login
set RHOSTS 10.10.10.10
set USER_FILE /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt
set PASS_FILE /usr/share/wordlists/seclists/Passwords/Common-Credentials/top-100-common-passwords.txt
run
```

## Contramedidas
- **Habilitar la autenticación** mediante Elasticsearch Security (x-pack) configurando usuarios y roles robustos.
- **Vincular el servicio a 127.0.0.1** (localhost) si el acceso remoto no es obligatorio.
- **Cifrar las comunicaciones** utilizando TLS/SSL para proteger los datos en tránsito.
- **Implementar listas de control de acceso (ACLs)** para restringir qué nodos y clientes pueden conectarse al cluster.
- **Deshabilitar la ejecución de scripts dinámicos** si no son necesarios, para mitigar posibles ataques de RCE (Remote Code Execution).
- **Mantener Elasticsearch actualizado** para corregir vulnerabilidades críticas.

## Referencias
- Elastic Documentation. (2024). Secure Elasticsearch. https://www.elastic.co/guide/en/elasticsearch/reference/current/secure-cluster.html
- HackTricks. (2024). 9200 - Pentesting Elasticsearch. https://book.hacktricks.xyz/network-services-pentesting/9200-pentesting-elasticsearch
- SecLists: /usr/share/wordlists/seclists/Passwords/Default-Credentials/elasticsearch-betterdefaultpasslist.txt
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
