# Enumeracion DNS

## Descripcion
Tecnica de reconocimiento activo que consiste en consultar servidores DNS de forma directa para descubrir subdominios y mapear la infraestructura DNS del objetivo. Segun *Mastering Kali Linux*, la enumeracion DNS moderna va mas alla de las transferencias de zona, incluyendo tecnicas como **NSEC Walking** para descubrir zonas firmadas por DNSSEC y **Cache Snooping** para identificar dominios visitados frecuentemente por los usuarios del servidor DNS consultado.

## Clasificacion
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: T1590.002 (Gather Victim Network Information: DNS)
- **Plataforma**: Multi
- **Dificultad**: Intermedia

## Herramientas
- **nslookup / dig** — Herramientas estandar de consulta DNS
- **dnsrecon** — Framework con soporte para brute force, cache snooping y transferencia de zona
- **amass** — Framework de enumeracion de subdominios con soporte para scripting (OAM)
- **subfinder** — Descubrimiento rapido de subdominios con fuentes multiples
- **ldns-walk** — Herramienta especializada en NSEC walking

## Comandos / Ejemplos

### NSEC Walking (Enumeracion de zonas DNSSEC)
```bash
ldns-walk @ns1.target.com target.com
```
Permite descubrir todos los registros de una zona si DNSSEC esta configurado incorrectamente usando registros NSEC.

### DNS Cache Snooping
```bash
dnsrecon -t snoop -n 8.8.8.8 -D subdomains.txt
```
Verifica si el servidor DNS (8.8.8.8) tiene en cache los dominios de la lista, indicando que han sido resueltos recientemente por usuarios de ese DNS.

### Uso Avanzado de Amass (Active mode)
```bash
amass enum -active -d target.com -ip -src
```
La opcion `-active` realiza consultas de fuerza bruta, extraccion de certificados SSL y consultas de zona, proporcionando la vision mas completa del objetivo.

### Intento de transferencia de zona (AXFR)
```bash
dig axfr @ns1.target.com target.com
```

## Contramedidas
- **Restringir AXFR**: Permitir transferencias de zona unicamente a IPs de servidores secundarios conocidos.
- **Implementar NSEC3**: Utilizar NSEC3 en lugar de NSEC para mitigar el walking mediante el uso de hashes de los nombres de dominio.
- **Limitar Recursion**: Configurar el servidor DNS para no permitir consultas recursivas desde el exterior (evita Cache Snooping).
- **Rate Limiting**: Aplicar limites de consultas para mitigar ataques de fuerza bruta de subdominios.

## Referencias
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- Kim, P. (2018). *The Hacker Playbook 3: Practical Guide to Penetration Testing*. Secure Planet.
- Notas del proyecto: notas-md/HNotes/Recon/Active Enumeration/nslookup.md
- MITRE Corporation. (2024). ATT&CK Technique T1590.002: Gather Victim Network Information: DNS. https://attack.mitre.org/techniques/T1590/002/
