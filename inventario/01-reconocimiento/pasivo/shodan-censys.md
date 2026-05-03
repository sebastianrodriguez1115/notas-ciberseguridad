# Shodan y Censys

## Descripción
Motores de búsqueda especializados en dispositivos conectados a internet. Según *Mastering Kali Linux*, estas herramientas permiten mapear la infraestructura del objetivo sin generar una sola alerta en sus sistemas. El uso de **facetas** (facets) permite agregar datos para identificar patrones, como versiones de software más comunes o países donde el objetivo tiene más presencia.

## Clasificación
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: T1596 (Search Open Technical Databases)
- **Plataforma**: Web
- **Dificultad**: Básica

## Herramientas
- **Shodan** (shodan.io) — Especializado en banners de servicio y dispositivos IoT
- **Censys** (censys.io) — Mayor foco en certificados SSL y hosts con escaneos masivos
- **shodan CLI** — Herramienta de linea de comandos para consultas y agregación de datos (stats)

## Comandos / Ejemplos

### Uso de Facetas para Agregación de Datos
```bash
shodan stats --facets port hostname:target.com
shodan stats --facets vuln hostname:target.com
```
Permite ver de forma agregada que puertos están más expuestos o que vulnerabilidades (CVEs) ha detectado Shodan en el dominio objetivo.

### Búsqueda por Vulnerabilidad Específica
```
vuln:CVE-2021-44228 org:"Target Corp"
```
Muestra directamente todos los activos de una organización que son vulnerables a Log4j (o cualquier otro CVE que Shodan indexe).

### Descubrimiento de Entornos de Desarrollo (Non-standard ports)
```
hostname:target.com port:8080,8443,8888,9000
```
Entornos de staging o desarrollo suelen ejecutarse en puertos no estándar para evitar escaneos simples, pero Shodan los indexa de forma predeterminada.

### Censys para búsqueda de hosts
```
(target.com) AND services.port: 443
```
Proporciona información detallada sobre el certificado SSL y el stack tecnológico detectado por Censys.

## Contramedidas
- **Deshabilitar Banners Informativos**: Configurar servidores para no exponer versiones de software que Shodan pueda indexar.
- **Implementar ACLs de Red**: Bloquear el acceso a puertos administrativos desde internet.
- **VPN para Administración**: No exponer paneles (Jenkins, RDP, SSH) directamente a la red pública.
- **Monitoreo Externo**: Realizar búsquedas periodicas en Shodan y Censys para conocer que activos propios están indexados.

## Referencias
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1596: Search Open Technical Databases. https://attack.mitre.org/techniques/T1596/
- Shodan. (s.f.). *Command-Line Interface: Stats*. https://help.shodan.io/command-line-interface/stats
