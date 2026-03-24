# Análisis de CORS (Cross-Origin Resource Sharing)

## Descripción
El análisis de vulnerabilidades de CORS consiste en identificar configuraciones incorrectas en las cabeceras HTTP que permiten a un dominio externo acceder a recursos restringidos de otra aplicación. Un atacante puede explotar estas debilidades para realizar exfiltración de datos sensibles (como tokens de sesión o información personal) mediante el uso de JavaScript en un sitio malicioso controlado por él.

## Clasificación
- **Fase**: Análisis de Vulnerabilidades
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
- **Plataforma**: Web
- **Dificultad**: Intermedia

## Herramientas
- **Burp Suite** (Proxy / Repeater) — permite interceptar y modificar cabeceras `Origin` para verificar reflexiones.
- **CORS-test** — herramienta automatizada para identificar configuraciones permisivas.

## Comandos / Ejemplos

### Reflexión básica de origen
```http
# Petición enviada por el atacante
GET /api/userData HTTP/1.1
Host: vulnerable.com
Origin: https://attacker.com
Cookie: session=xyz123

# Respuesta vulnerable reflejando el origen
HTTP/1.1 200 OK
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```

### Confianza en el origen 'null'
```http
# Petición con origen null (útil para ataques desde iframes o archivos locales)
GET /api/userData HTTP/1.1
Host: vulnerable.com
Origin: null

# Respuesta vulnerable
HTTP/1.1 200 OK
Access-Control-Allow-Origin: null
Access-Control-Allow-Credentials: true
```

## Contramedidas
- Configurar una lista blanca estricta de dominios permitidos en `Access-Control-Allow-Origin`.
- Evitar el uso de `Access-Control-Allow-Origin: *` cuando `Access-Control-Allow-Credentials` es true.
- No confiar ciegamente en la cabecera `Origin` sin validación previa en el servidor.

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
- Notas del proyecto: notas-md/HNotes/HNotes/Burp Suite Labs/CORS/
