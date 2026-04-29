# Escaneo de Vulnerabilidades Web con Nikto

## Descripción
Nikto es un escaner web open source que realiza pruebas automatizadas contra servidores HTTP en busca de configuraciones inseguras, archivos y programas peligrosos, versiones de servidor vulnerables y cabeceras de seguridad ausentes. Genera una lista de hallazgos con referencias a CVEs y CWEs cuando aplica. Es altamente ruidoso y facil de detectar por firewalls e IDS/IPS; por ello se usa en pentests donde la detección no es una preocupacion o despues de confirmar ausencia de WAF.

## Clasificación
- **Fase**: Enumeración
- **MITRE ATT&CK**: T1595.002 (Active Scanning: Vulnerability Scanning)
- **Plataforma**: Web
- **Dificultad**: Básica

## Herramientas
- **nikto** — escaner web automatizado con base de datos de checks actualizable

## Comandos / Ejemplos

```bash
# Escaneo basico
nikto -h http://192.168.20.33

# Especificar puerto no estandar
nikto -h http://TARGET -p 8080

# Con autenticacion HTTP Basic
nikto -h http://TARGET -id usuario:contrasena

# Escaneo sobre HTTPS
nikto -h https://TARGET -ssl

# Guardar resultado en archivo
nikto -h http://TARGET -o resultado.txt -Format txt

# Aumentar tuning (tipo de checks a realizar)
# -Tuning 9 → pruebas de inyeccion SQL
nikto -h http://TARGET -Tuning 9
```

**Tipos de hallazgos reportados:**
- Archivos peligrosos: `/phpinfo.php`, `/test.php`, `/admin/`, `/backup/`
- Cabeceras de seguridad ausentes: `X-Frame-Options`, `Strict-Transport-Security`, `Content-Security-Policy`
- Versiones vulnerables de servidor con CVE referenciado
- Configuraciones inseguras: directory listing habilitado, métodos HTTP peligrosos

**Advertencia:** Nikto genera un volumen alto de peticiones y es facilmente detectable. Evitar en pruebas donde se requiere sigilo.

## Contramedidas
- Desplegar un WAF (Web Application Firewall) que bloquee patrones de escaneo conocidos
- Implementar rate limiting para bloquear IPs que generen demasiadas peticiones
- Revisar periodicamente la configuración del servidor web con herramientas equivalentes
- Agregar cabeceras de seguridad HTTP: `X-Frame-Options`, `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`
- Eliminar archivos de ejemplo, debug y configuración del entorno de producción

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1595.002: Active Scanning: Vulnerability Scanning. https://attack.mitre.org/techniques/T1595/002/
