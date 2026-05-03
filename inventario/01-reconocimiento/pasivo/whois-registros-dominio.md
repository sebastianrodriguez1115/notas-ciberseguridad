---
title: WHOIS y Registros de Dominio
slug: whois-registros-dominio
aliases: [WHOIS, Reverse WHOIS, ASN Lookup, Domain Registration]
fase: [Reconocimiento]
plataforma: Multi
dificultad: Básica
mitre: [T1596.002]
related: [dns-pasivo, recoleccion-emails]
learning_refs: []
---

# WHOIS y Registros de Dominio

## Descripción
Consulta de bases de datos WHOIS para obtener información de registro de dominios e IPs. Según *Mastering Kali Linux*, el WHOIS es la base para el **mapeo de holdings empresariales** mediante técnicas de **Reverse WHOIS**. Al identificar el nombre del registrante o su correo corporativo, se pueden descubrir otros dominios propiedad de la misma organización que podrian estar menos protegidos o ser desconocidos para el equipo de seguridad.

## Herramientas
- **whois (CLI)** — Cliente estándar para consultas básicas de dominios e IPs
- **ViewDNS.info** — Plataforma para búsqueda Reverse WHOIS y mapeo de red
- **Domaintools / WHOISXMLAPI** — Herramientas comerciales con bases de datos historicas masivas
- **Team Cymru WHOIS** — Especializado en resolución de ASN (Autonomous System Number)

## Comandos / Ejemplos

### Mapeo Corporativo via Reverse WHOIS
Utilizando ViewDNS.info o APIs similares, se puede buscar por el nombre de la empresa: `target corp`. Esto revela dominios registrados bajo la misma identidad que pueden ser entornos de prueba (`target-staging.com`) o marcas subsidiarias.

### Análisis de ASN para Descubrimiento de Rango IP
```bash
whois -h whois.cymru.com " -v 8.8.8.8"
```
Permite identificar a que entidad pertenece un bloque de IPs y su tamaño. Util para mapear toda la infraestructura de red pública de una organización.

### Identificación de Bloques IP en ARIN/RIPE
```bash
whois -h whois.arin.net "n + Target Corp"
```
Busca todos los bloques de red asignados oficialmente a la organización "Target Corp" en el registro regional correspondiente.

## Contramedidas
- **WHOIS Privacy (Proxy)**: Medida básica para ocultar los datos del registrante real en dominios públicos.
- **Utilizar Correos Genericos**: Registrar dominios con correos como `it-dept@target.com` en lugar de correos personales para dificultar el perfilado de administradores.
- **Segmentación de Registrantes**: Registrar activos críticos a través de diferentes registradores para dificultar el mapeo completo de la infraestructura.

## Referencias
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1596.002: Search Open Technical Databases: WHOIS. https://attack.mitre.org/techniques/T1596/002/
