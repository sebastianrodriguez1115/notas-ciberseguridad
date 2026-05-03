---
title: Análisis de Vulnerabilidades: Seguridad de Cabeceras HTTP
slug: analisis-seguridad-cabeceras
aliases: ["Análisis de Vulnerabilidades: Seguridad de Cabeceras HTTP"]
fase: [Análisis de Vulnerabilidades]
plataforma: Web
dificultad: Básica
mitre: [T1595.002]
related: []
learning_refs: []
---

# Análisis de Vulnerabilidades: Seguridad de Cabeceras HTTP

## Descripción
Las cabeceras de respuesta HTTP permiten a los servidores web indicar a los navegadores cómo comportarse respecto a la seguridad del contenido servido. La ausencia o configuración incorrecta de estas cabeceras puede facilitar ataques como XSS, Clickjacking o Sniffing de contenido. El análisis de cabeceras es una fase fundamental en cualquier auditoría web.

## Herramientas
- **curl** — Herramienta de línea de comandos para inspeccionar cabeceras de respuesta HTTP de forma rápida.
- **Navegador** (Pestaña Network) — Interfaz para analizar la seguridad de las cabeceras durante la navegación.
- **OWASP ZAP** — Escáner automatizado que incluye análisis detallado del cumplimiento de cabeceras de seguridad.
- **Securityheaders.com** — Herramienta en línea para calificar la configuración de seguridad de las cabeceras HTTP.

## Comandos / Ejemplos
Verificar cabeceras de un sitio con `curl`:
```bash
curl -I https://target.com
```

Identificar cabeceras faltantes comunes:
- `Content-Security-Policy` (CSP)
- `Strict-Transport-Security` (HSTS)
- `X-Frame-Options` (Previene Clickjacking)
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy`

Verificar configuración de cookies (Secure/HttpOnly/SameSite):
```bash
curl -i https://target.com | grep "Set-Cookie"
```

Uso de scripts personalizados de Nmap:
```bash
nmap -p 443 --script http-security-headers <target_ip>
```

## Contramedidas
- Configurar el servidor web (Apache, Nginx, IIS) para incluir cabeceras de seguridad por defecto.
- Implementar `Strict-Transport-Security` para forzar HTTPS.
- Configurar `Content-Security-Policy` restrictiva (evitar `unsafe-inline`).
- Deshabilitar cabeceras que revelen información técnica (`Server`, `X-Powered-By`).

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Easttom, C. (2016). *Computer Security Fundamentals*. Pearson IT Certification.
- Hertzog, R., & O'Gorman, J. (2017). *Kali Linux Revealed: Mastering the Penetration Testing Distribution*. OffSec Press.
