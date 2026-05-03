---
title: Recolección de Emails
slug: recoleccion-emails
aliases: [Email Harvesting, theHarvester, OSINT Email, Email OSINT]
fase: [Reconocimiento]
plataforma: Multi
dificultad: Básica
mitre: [T1589.002]
related: [google-dorking, whois-registros-dominio]
learning_refs: []
---

# Recolección de Emails

## Descripción
Descubrimiento de direcciones de correo electrónico asociadas a una organización objetivo. Según *Mastering Kali Linux*, la recolección moderna incluye la búsqueda en **brechas de datos historicas** para encontrar no solo emails, sino credenciales filtradas que pueden ser probadas en ataques de password spraying o reutilización de contraseñas.

## Herramientas
- **theHarvester** — Recolección automatizada de emails en múltiples fuentes (scraping + APIs)
- **Hunter.io** — Especializado en patrones de email corporativos y descubrimiento de contactos
- **Have I Been Pwned** — Verificación de emails en brechas de datos públicas
- **DeHashed / IntelX** — Servicios de inteligencia sobre brechas de datos para búsquedas más profundas

## Comandos / Ejemplos

### theHarvester con múltiples fuentes
```bash
theHarvester -d target.com -b all -l 500
```
La opción `-b all` busca en Google, Bing, LinkedIn, Shodan, VirusTotal y otras fuentes simultaneamente.

### Identificación de Patrones de Email (Hunter.io)
Hunter.io revela que el patrón más común es `{first}.{last}@target.com`. Esto permite generar listas de emails para ataques de fuerza bruta basándose en nombres obtenidos de LinkedIn.

### Búsqueda en Brechas de Datos (DeHashed API)
```bash
curl -u <API_KEY>: "https://api.dehashed.com/search?query=domain:target.com"
```
Permite obtener una lista de emails y sus contraseñas (en texto claro o hash) filtradas en brechas historicas de sitios de terceros.

## Contramedidas
- **Protección de Privacidad WHOIS**: No registrar dominios con correos corporativos reales o personales expuestos.
- **Implementar MFA**: Medida crítica para anular la utilidad de credenciales filtradas en brechas.
- **Detección de Fugas de Datos**: Utilizar servicios de monitoreo de brechas de datos para ser notificado cuando un correo corporativo se vea comprometido.
- **Politicas de Contraseñas Unicas**: Evitar el reuso de contraseñas corporativas en servicios de terceros.

## Referencias
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1589.002: Gather Victim Identity Information: Email Addresses. https://attack.mitre.org/techniques/T1589/002/
- Hunt, T. (s.f.). *Have I Been Pwned*. https://haveibeenpwned.com/
