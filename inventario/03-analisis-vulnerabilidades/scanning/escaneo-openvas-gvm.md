# Escaneo de Vulnerabilidades con OpenVAS / GVM

## Descripción
OpenVAS (Open Vulnerability Assessment System) es un framework robusto para el escaneo y la gestión de vulnerabilidades. Ahora mantenido bajo el nombre Greenbone Vulnerability Management (GVM), es capaz de realizar miles de pruebas de vulnerabilidad de red (NVT) actualizadas regularmente. Es una herramienta fundamental para realizar evaluaciones exhaustivas en entornos empresariales.

## Clasificación
- **Fase**: Análisis de Vulnerabilidades
- **MITRE ATT&CK**: T1595.002 (Active Scanning: Vulnerability Scanning)
- **Plataforma**: Multi
- **Dificultad**: Intermedia

## Herramientas
- **GVM / OpenVAS** — Framework de escaneo y gestión de vulnerabilidades de código abierto.
- **Greenbone Security Assistant** (GSA) — Interfaz gráfica basada en web para la gestión de tareas de escaneo.
- **gvm-cli** — Herramienta de línea de comandos para interactuar con el protocolo de gestión de Greenbone.

## Comandos / Ejemplos
Actualizar la base de datos de vulnerabilidades (Feeds):
```bash
gvm-feed-update
```

Iniciar un escaneo básico mediante línea de comandos (utilizando `gvm-cli`):
```bash
gvm-cli --gmp-username admin --gmp-password password socket --xml "<create_task><name>Escaneo Red Interna</name><config id='74db1332-0147-4722-8538-adcfc66bc2c0'/><target id='...' /></create_task>"
```

Configuración de escaneos autenticados (Credenciales SSH):
Para detectar vulnerabilidades locales en Linux, se deben proporcionar credenciales de usuario con privilegios mínimos o root para que GVM inspeccione parches y paquetes obsoletos.

## Contramedidas
- Priorizar la corrección de vulnerabilidades con puntuación CVSS crítica.
- Automatizar escaneos semanales o mensuales para detectar regresiones de seguridad.
- Utilizar firewalls de próxima generación (NGFW) para detectar tráfico anómalo generado por escáneres.
- Implementar una política de gestión de parches rigurosa basada en los informes de GVM.

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Easttom, C. (2016). *Computer Security Fundamentals*. Pearson IT Certification.
