# Escaneo de Vulnerabilidades

## Descripcion
Tecnica que utiliza herramientas automatizadas para identificar vulnerabilidades conocidas, errores de configuracion y debilidades de seguridad en sistemas y aplicaciones web objetivo. Los escaneres comparan los servicios detectados contra bases de datos de vulnerabilidades (CVE, NVD) y realizan pruebas activas para confirmar la existencia de fallos explotables. Segun *Mastering Kali Linux*, un escaneo efectivo debe diferenciar entre escaneos **no autenticados** (vision externa del atacante) y **autenticados** (vision interna con privilegios), siendo estos ultimos mucho mas precisos al analizar software instalado y configuraciones locales.

## Clasificacion
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: T1595.002 (Active Scanning: Vulnerability Scanning)
- **Plataforma**: Multi
- **Dificultad**: Intermedia

## Herramientas
- **nikto** — Escaner de servidores web que detecta configuraciones peligrosas y archivos por defecto
- **Nessus** — Referencia industrial para escaneo de vulnerabilidades con reportes ejecutivos y tecnicos
- **OpenVAS** — Alternativa open source potente con un feed de NVT (Network Vulnerability Tests) activo
- **nmap NSE scripts** — Extensiones de nmap para deteccion especifica de fallos
- **Nuclei** — Escaner moderno basado en templates, extremadamente rapido y personalizable para vulnerabilidades web modernas

## Comandos / Ejemplos

### Escaneo Autenticado (Ejemplo conceptual Nessus/OpenVAS)
*Configuracion*: Se proporcionan credenciales (SSH para Linux, SMB para Windows) al escaner.
*Resultado*: Permite detectar vulnerabilidades en librerias locales, parches de seguridad faltantes (KB en Windows) y configuraciones de registro que no son visibles desde la red.

### Uso Avanzado de nmap NSE por Categorias
```bash
nmap --script safe 192.168.1.10         # Scripts que no afectan la estabilidad
nmap --script vuln 192.168.1.10         # Scripts especificos de vulnerabilidades
nmap --script "vuln and safe" 192.168.1.10 # Combinacion logica de categorias
nmap --script exploit 192.168.1.10       # CUIDADO: intenta explotar activamente, no solo escanear
```

### Escaneo de Vulnerabilidades Web Moderno (Nuclei)
```bash
nuclei -u https://target.com -t cves/ -t exposures/
```
Nuclei permite usar plantillas creadas por la comunidad para detectar fallos muy recientes (0-days recientes) de forma mas eficiente que Nikto.

### Gestion de Resultados (Libros de referencia)
- **Falso Positivo**: El escaner reporta una vulnerabilidad que no existe (ej: version de banner no coincide con el parche aplicado).
- **Falso Negativo**: El escaner no detecta una vulnerabilidad real (frecuente en escaneos no autenticados).
- **Validacion Manual**: Paso obligatorio segun *The Hacker Playbook 3* antes de proceder a la explotacion para evitar bloqueos innecesarios por IDS.

## Contramedidas
- **Gestion de parches (Patch Management)**: Implementar un ciclo regular basado en la severidad (CVSS).
- **Escaneos Recurrentes**: Realizar escaneos mensuales o tras cada cambio significativo en la infraestructura.
- **WAF/IPS**: Mitigar temporalmente vulnerabilidades que no pueden ser parcheadas inmediatamente (Virtual Patching).
- **Hardening**: Seguir guias como CIS Benchmarks para reducir la superficie de ataque independientemente de las vulnerabilidades.

## Referencias
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- Sinha, S. (2017). *Metasploit for Beginners*. Packt Publishing.
- Kim, P. (2018). *The Hacker Playbook 3: Practical Guide to Penetration Testing*. Secure Planet.
- MITRE Corporation. (2024). ATT&CK Technique T1595.002: Active Scanning: Vulnerability Scanning. https://attack.mitre.org/techniques/T1595/002/
