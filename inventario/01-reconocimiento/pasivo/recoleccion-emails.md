# Recoleccion de Emails

## Descripcion
Descubrimiento de direcciones de correo electronico asociadas a una organizacion objetivo. Segun *Mastering Kali Linux*, la recoleccion moderna incluye la busqueda en **brechas de datos historicas** para encontrar no solo emails, sino credenciales filtradas que pueden ser probadas en ataques de password spraying o reutilizacion de contraseñas.

## Clasificacion
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: T1589.002 (Gather Victim Identity Information: Email Addresses)
- **Plataforma**: Multi
- **Dificultad**: Basica

## Herramientas
- **theHarvester** — Recoleccion automatizada de emails en multiples fuentes (scraping + APIs)
- **Hunter.io** — Especializado en patrones de email corporativos y descubrimiento de contactos
- **Have I Been Pwned** — Verificacion de emails en brechas de datos publicas
- **DeHashed / IntelX** — Servicios de inteligencia sobre brechas de datos para busquedas mas profundas

## Comandos / Ejemplos

### theHarvester con multiples fuentes
```bash
theHarvester -d target.com -b all -l 500
```
La opcion `-b all` busca en Google, Bing, LinkedIn, Shodan, VirusTotal y otras fuentes simultaneamente.

### Identificacion de Patrones de Email (Hunter.io)
Hunter.io revela que el patron mas comun es `{first}.{last}@target.com`. Esto permite generar listas de emails para ataques de fuerza bruta basandose en nombres obtenidos de LinkedIn.

### Busqueda en Brechas de Datos (DeHashed API)
```bash
curl -u <API_KEY>: "https://api.dehashed.com/search?query=domain:target.com"
```
Permite obtener una lista de emails y sus contraseñas (en texto claro o hash) filtradas en brechas historicas de sitios de terceros.

## Contramedidas
- **Proteccion de Privacidad WHOIS**: No registrar dominios con correos corporativos reales o personales expuestos.
- **Implementar MFA**: Medida critica para anular la utilidad de credenciales filtradas en brechas.
- **Deteccion de Fugas de Datos**: Utilizar servicios de monitoreo de brechas de datos para ser notificado cuando un correo corporativo se vea comprometido.
- **Politicas de Contraseñas Unicas**: Evitar el reuso de contraseñas corporativas en servicios de terceros.

## Referencias
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1589.002: Gather Victim Identity Information: Email Addresses. https://attack.mitre.org/techniques/T1589/002/
- Hunt, T. (s.f.). *Have I Been Pwned*. https://haveibeenpwned.com/
