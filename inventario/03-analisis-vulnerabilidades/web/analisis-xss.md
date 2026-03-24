# Análisis de Vulnerabilidades: Cross-Site Scripting (XSS)

## Descripción
El Cross-Site Scripting (XSS) es una vulnerabilidad de seguridad que permite a un atacante inyectar scripts maliciosos (generalmente JavaScript) en páginas web vistas por otros usuarios. Estos scripts pueden ser utilizados para robar cookies de sesión, realizar redirecciones maliciosas o modificar el contenido de la página.

## Clasificación
- **Fase**: Análisis de Vulnerabilidades
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
- **Plataforma**: Web
- **Dificultad**: Intermedia

## Herramientas
- **Burp Suite** — Plataforma integral con escáner de vulnerabilidades y soporte para extensiones avanzadas de XSS.
- **OWASP ZAP** — Herramienta de seguridad para la detección de vulnerabilidades de scripting entre sitios.
- **SecLists** — Colección de payloads XSS para probar diferentes contextos de ejecución y evasión de filtros.
- **Navegador** — Entorno fundamental para la ejecución y validación de pruebas de concepto XSS.

## Comandos / Ejemplos
Fuzzing básico con `ffuf` y SecLists:
```bash
ffuf -u http://target.com/search?q=FUZZ -w /usr/share/seclists/Fuzzing/XSS/XSS-Bypass-Strings-Small.txt -mr "<script>|alert\("
```

Prueba manual de XSS Reflejado:
```javascript
<script>alert('XSS_Test')</script>
<img src=x onerror=alert('XSS')>
```

Uso de herramientas automáticas (ej. XSStrike):
```bash
python3 xsstrike.py -u "http://target.com/search?q=query"
```

## Contramedidas
- Escapar/Codificar la salida de datos dinámicos (Output Encoding).
- Implementar una Política de Seguridad de Contenido (CSP - Content Security Policy).
- Utilizar el atributo `HttpOnly` en las cookies de sesión para prevenir su acceso vía JS.
- Validar las entradas del lado del servidor (Input Validation).

## Referencias
- Harper, A., et al. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook*. McGraw-Hill Education.
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
