# Análisis de Vulnerabilidades con Nessus

## Descripción
Nessus es uno de los escáneres de vulnerabilidades más utilizados en la industria para identificar debilidades de seguridad en sistemas operativos, aplicaciones, bases de datos y dispositivos de red. Su metodología se basa en el escaneo activo de activos para detectar parches faltantes, configuraciones inseguras y vulnerabilidades conocidas (CVEs).

## Clasificación
- **Fase**: Análisis de Vulnerabilidades
- **MITRE ATT&CK**: T1595.002 (Active Scanning: Vulnerability Scanning)
- **Plataforma**: Multi
- **Dificultad**: Básica

## Herramientas
- **Nessus** (`Advanced Scan`, `Policy Compliance`) — plataforma principal para el escaneo y gestión de vulnerabilidades.

## Comandos / Ejemplos

### Flujo de trabajo en Nessus
1. **Configuración de Políticas**: Crear una política de "Advanced Scan" con plugins específicos seleccionados.
2. **Definición de Targets**: Ingresar rangos de IP (ej. `192.168.1.0/24`) o dominios.
3. **Escaneo con Credenciales**: Configurar credenciales SSH o SMB para realizar auditorías internas más profundas.
4. **Análisis de Resultados**: Filtrar por severidad (Critical, High, Medium, Low) y priorizar la remediación.

### Identificación de activos críticos
```text
# Ejemplo de hallazgo típico en reporte
Vulnerabilidad: MS17-010 (EternalBlue)
Severidad: CRITICAL
ID Nessus: 97833
CVE: CVE-2017-0143
```

## Contramedidas
- Ejecutar escaneos periódicos y programados para detectar nuevas vulnerabilidades.
- Integrar Nessus con sistemas de gestión de parches para automatizar la remediación.
- Realizar escaneos autenticados para obtener una visión completa de la superficie de ataque.

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1595.002: Active Scanning: Vulnerability Scanning. https://attack.mitre.org/techniques/T1595/002/
