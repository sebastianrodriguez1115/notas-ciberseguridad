# DNS Pasivo

## Descripcion
Recopilacion de informacion DNS sin consultar directamente los servidores DNS del objetivo. Segun *Mastering Kali Linux*, el DNS Pasivo utiliza repositorios de inteligencia de amenazas que han recolectado resoluciones DNS a lo largo del tiempo. Es ideal para descubrir **subdominios historicos** que han sido eliminados del DNS actual pero cuyos servicios podrian seguir activos en IPs antiguas.

## Clasificacion
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: T1590.002 (Gather Victim Network Information: DNS)
- **Plataforma**: Multi
- **Dificultad**: Basica

## Herramientas
- **DNSDumpster** (dnsdumpster.com) — Visualizacion grafica de relaciones DNS
- **SecurityTrails** (securitytrails.com) — Repositorio lider en historial de registros DNS (A, MX, CNAME)
- **VirusTotal** — Relaciones pasivas de malware con dominios y resoluciones IP
- **Project Sonar (Rapid7)** — Datasets publicos de escaneos masivos de todo el espacio de direccionamiento IP de internet

## Comandos / Ejemplos

### Consulta de Historial DNS (SecurityTrails)
Permite ver que IPs resolvian un dominio hace años. Util para encontrar servidores de correo o bases de datos que no fueron decomisionados correctamente.

### Analisis de Project Sonar via CLI
```bash
# Ejemplo de extraccion de registros DNS de los datasets de Rapid7
zgrep "target.com" sonar.fdns_v2.json.gz | jq '.'
```
Esta tecnica proporciona visibilidad sobre subdominios que jamas fueron anunciados publicamente pero fueron captados por los escaneres de Rapid7.

### Uso de Sublist3r para Multiples Fuentes Pasivas
```bash
sublist3r -d target.com -e google,bing,shodan,virustotal
```
Combina scraping de motores de busqueda y APIs de servicios de inteligencia DNS.

## Contramedidas
- **Descomisionar Correctamente**: Eliminar los servicios del servidor fisico ademas de borrar el registro DNS.
- **Evitar el Reuso de IPs Publicas**: Para sistemas criticos, si es posible, rotar el direccionamiento IP tras eliminar el DNS.
- **Split-Horizon DNS**: Prevenir que registros de subdominios internos se filtren a servidores DNS publicos que puedan ser capturados por datasets.

## Referencias
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1590.002: Gather Victim Network Information: DNS. https://attack.mitre.org/techniques/T1590/002/
- Rapid7. (s.f.). *Project Sonar: Open Data*. https://opendata.rapid7.com/
