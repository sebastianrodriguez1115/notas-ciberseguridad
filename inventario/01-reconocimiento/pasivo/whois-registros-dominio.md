# WHOIS y Registros de Dominio

## Descripcion
Consulta de bases de datos WHOIS para obtener informacion de registro de dominios e IPs. Segun *Mastering Kali Linux*, el WHOIS es la base para el **mapeo de holdings empresariales** mediante tecnicas de **Reverse WHOIS**. Al identificar el nombre del registrante o su correo corporativo, se pueden descubrir otros dominios propiedad de la misma organizacion que podrian estar menos protegidos o ser desconocidos para el equipo de seguridad.

## Clasificacion
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: T1596.002 (Search Open Technical Databases: WHOIS)
- **Plataforma**: Multi
- **Dificultad**: Basica

## Herramientas
- **whois (CLI)** — Cliente estandar para consultas basicas de dominios e IPs
- **ViewDNS.info** — Plataforma para busqueda Reverse WHOIS y mapeo de red
- **Domaintools / WHOISXMLAPI** — Herramientas comerciales con bases de datos historicas masivas
- **Team Cymru WHOIS** — Especializado en resolucion de ASN (Autonomous System Number)

## Comandos / Ejemplos

### Mapeo Corporativo via Reverse WHOIS
Utilizando ViewDNS.info o APIs similares, se puede buscar por el nombre de la empresa: `target corp`. Esto revela dominios registrados bajo la misma identidad que pueden ser entornos de prueba (`target-staging.com`) o marcas subsidiarias.

### Analisis de ASN para Descubrimiento de Rango IP
```bash
whois -h whois.cymru.com " -v 8.8.8.8"
```
Permite identificar a que entidad pertenece un bloque de IPs y su tamaño. Util para mapear toda la infraestructura de red publica de una organizacion.

### Identificacion de Bloques IP en ARIN/RIPE
```bash
whois -h whois.arin.net "n + Target Corp"
```
Busca todos los bloques de red asignados oficialmente a la organizacion "Target Corp" en el registro regional correspondiente.

## Contramedidas
- **WHOIS Privacy (Proxy)**: Medida basica para ocultar los datos del registrante real en dominios publicos.
- **Utilizar Correos Genericos**: Registrar dominios con correos como `it-dept@target.com` en lugar de correos personales para dificultar el perfilado de administradores.
- **Segmentacion de Registrantes**: Registrar activos criticos a traves de diferentes registradores para dificultar el mapeo completo de la infraestructura.

## Referencias
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- Notas del proyecto: notas-md/HNotes/Recon/Active Enumeration/whois.md
- Notas del proyecto: notas-md/HNotes/Recon/Active Enumeration/Reverse whois.md
- MITRE Corporation. (2024). ATT&CK Technique T1596.002: Search Open Technical Databases: WHOIS. https://attack.mitre.org/techniques/T1596/002/
