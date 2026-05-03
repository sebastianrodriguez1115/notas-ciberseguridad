---
title: Análisis de Open Redirect
slug: analisis-open-redirect
aliases: [Análisis de Open Redirect]
fase: [Análisis de Vulnerabilidades]
plataforma: Web
dificultad: Básica
mitre: [T1190]
related: []
learning_refs: []
---

# Análisis de Open Redirect

## Descripción
El redireccionamiento abierto ocurre cuando una aplicación web redirige al usuario a una URL externa especificada a través de un parámetro de entrada sin una validación adecuada. Aunque a menudo se considera de baja severidad, es una herramienta crítica en campañas de phishing y puede encadenarse con ataques de robo de tokens (OAuth) o SSRF.

## Herramientas
- **Burp Suite** — para identificar parámetros de redirección (ej. `?next=`, `?url=`, `?redirect=`).
- **ffuf** — para fuzzear parámetros con listas de bypasses de redirección.

## Comandos / Ejemplos

### Escenario básico de explotación
```text
# URL legítima que redirige a un sitio controlado por el atacante
https://vulnerable.com/login?redirect=https://attacker.com/malware
```

### Técnicas de bypass comunes
```text
# Uso de doble slash
https://vulnerable.com/login?redirect=//attacker.com

# Uso del carácter @ para confundir al navegador
https://vulnerable.com/login?redirect=https://vulnerable.com@attacker.com

# Redirección relativa que incluye dominios externos
https://vulnerable.com/login?redirect=/\attacker.com
```

## Contramedidas
- Evitar el uso de redirecciones basadas en parámetros de usuario.
- Implementar una lista blanca de dominios permitidos para las redirecciones.
- Utilizar redirecciones locales (relativas) siempre que sea posible.

## Referencias
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
