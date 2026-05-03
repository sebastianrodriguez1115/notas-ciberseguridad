# Transparencia de Certificados (Certificate Transparency)

## Descripción
Consulta de logs de Certificate Transparency (CT) para descubrir subdominios e infraestructura asociada. Según *The Hacker Playbook 3*, la transparencia de certificados es una de las fuentes de inteligencia más valiosas para descubrir **subdominios de desarrollo o staging** que a menudo están menos protegidos que los de producción. La clave reside en analizar el campo **SAN (Subject Alternative Name)** de los certificados emitidos.

## Clasificación
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: T1596.003 (Search Open Technical Databases: Digital Certificates)
- **Plataforma**: Web
- **Dificultad**: Básica

## Herramientas
- **crt.sh** — Interfaz web para consultar logs de CT de forma masiva
- **Censys Certificates** — Búsqueda avanzada y filtrado de certificados SSL/TLS
- **certspotter** — Herramienta para monitorizar la emisión de nuevos certificados en tiempo real
- **facebook-ct-monitor** — Herramienta de Facebook para recibir alertas de nuevos certificados para dominios de interes

## Comandos / Ejemplos

### Descubrimiento de Infraestructura Oculta via SAN
Al emitir un certificado wildcard (*.target.com), el campo SAN puede revelar dominios adicionales como `api-staging.target-internal.com` que no aparecen en registros DNS públicos pero que comparten el mismo certificado.

### Extracción de subdominios via crt.sh (Automatizada)
```bash
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sort -u
```
El comodin `%25` actua como un `%` de SQL para buscar todos los certificados que contengan el dominio en su nombre.

### Identificar Certificados de Infraestructura Crítica
Buscar certificados emitidos para paneles VPN o administración (ej: `vpn.target.com`, `admin.target.com`) que suelen utilizar certificados públicos para evitar errores de navegador en sus empleados.

## Contramedidas
- **Monitorizar Logs de CT**: Implementar alertas para conocer de inmediato cuando se emite un certificado para un dominio de la organización.
- **Implementar CAA (Certificate Authority Authorization)**: Registro DNS que específica que CAs están autorizadas a emitir certificados para el dominio.
- **Evitar Certificados Wildcard para Dominios Internos**: Utilizar certificados separados o CAs internas para infraestructura que no debe ser visible desde el exterior.

## Referencias
- Kim, P. (2018). *The Hacker Playbook 3: Practical Guide to Penetration Testing*. Secure Planet.
- MITRE Corporation. (2024). ATT&CK Technique T1596.003: Search Open Technical Databases: Digital Certificates. https://attack.mitre.org/techniques/T1596/003/
- Google. (s.f.). *Certificate Transparency*. https://certificate.transparency.dev/
