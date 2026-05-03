---
title: Escaneo de Vulnerabilidades
slug: escaneo-vulnerabilidades
aliases: [Vulnerability Scanning, Nessus Scan, OpenVAS Scan, Nuclei]
fase: [Reconocimiento]
plataforma: Multi
dificultad: Intermedia
mitre: [T1595.002]
related: [escaneo-puertos, fingerprinting-os-servicios]
learning_refs: []
---

# Escaneo de Vulnerabilidades

## Descripción
Técnica que utiliza herramientas automatizadas para identificar vulnerabilidades conocidas, errores de configuración y debilidades de seguridad en sistemas y aplicaciones web objetivo. Los escáneres comparan los servicios detectados contra bases de datos de vulnerabilidades (CVE, NVD) y realizan pruebas activas para confirmar la existencia de fallos explotables. Según *Mastering Kali Linux*, un escaneo efectivo debe diferenciar entre escaneos **no autenticados** (visión externa del atacante) y **autenticados** (visión interna con privilegios), siendo estos últimos mucho más precisos al analizar software instalado y configuraciones locales.

## Herramientas
- **nikto** — Escáner de servidores web que detecta configuraciones peligrosas y archivos por defecto
- **Nessus** — Referencia industrial para escaneo de vulnerabilidades con reportes ejecutivos y técnicos
- **OpenVAS** — Alternativa open source potente con un feed de NVT (Network Vulnerability Tests) activo
- **nmap NSE scripts** — Extensiones de nmap para detección específica de fallos
- **Nuclei** — Escáner moderno basado en templates, extremadamente rápido y personalizable para vulnerabilidades web modernas

## Comandos / Ejemplos

### Escaneo Autenticado (Ejemplo conceptual Nessus/OpenVAS)
*Configuración*: Se proporcionan credenciales (SSH para Linux, SMB para Windows) al escáner.
*Resultado*: Permite detectar vulnerabilidades en librerías locales, parches de seguridad faltantes (KB en Windows) y configuraciones de registro que no son visibles desde la red.

### Uso Avanzado de nmap NSE por Categorías
```bash
nmap --script safe 192.168.1.10         # Scripts que no afectan la estabilidad
nmap --script vuln 192.168.1.10         # Scripts específicos de vulnerabilidades
nmap --script "vuln and safe" 192.168.1.10 # Combinación lógica de categorías
nmap --script exploit 192.168.1.10       # CUIDADO: intenta explotar activamente, no solo escanear
```

### Escaneo de Vulnerabilidades Web Moderno (Nuclei)
```bash
nuclei -u https://target.com -t cves/ -t exposures/
```
Nuclei permite usar plantillas creadas por la comunidad para detectar fallos muy recientes (0-days recientes) de forma más eficiente que Nikto.

### Gestion de Resultados (Libros de referencia)
- **Falso Positivo**: El escáner reporta una vulnerabilidad que no existe (ej: versión de banner no coincide con el parche aplicado).
- **Falso Negativo**: El escáner no detecta una vulnerabilidad real (frecuente en escaneos no autenticados).
- **Validación Manual**: Paso obligatorio según *The Hacker Playbook 3* antes de proceder a la explotación para evitar bloqueos innecesarios por IDS.

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
