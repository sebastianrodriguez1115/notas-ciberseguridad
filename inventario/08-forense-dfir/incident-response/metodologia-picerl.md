# Incident Response: Metodología PICERL

## Descripción
El Respuesta a Incidentes (Incident Response, IR) es el proceso organizado para manejar las consecuencias de un ataque cibernético o brecha de seguridad. La metodología PICERL (desarrollada por SANS) proporciona un marco estructurado para contener y mitigar ataques, minimizando el impacto en el negocio y asegurando la recuperación efectiva de los sistemas afectados.

## Clasificación
- **Fase**: Forense y DFIR
- **MITRE ATT&CK**: N/A (Metodología de Gestión)
- **Plataforma**: Multi
- **Dificultad**: Intermedia

## Fases del Ciclo PICERL

### 1. Preparación (Preparation)
La fase más importante, realizada antes de un incidente.
- Creación de políticas de IR, formación del equipo (CSIRT), preparación de herramientas forenses y kits de respuesta.
- Implementación de controles preventivos (EDR, SIEM, firewalls).

### 2. Identificación (Identification)
Detección de actividad sospechosa y confirmación del incidente.
- Análisis de logs, alertas de seguridad y reportes de usuarios.
- Determinar el alcance (fijar el "blast radius") y la gravedad del compromiso.

### 3. Contención (Containment)
Evitar que el ataque se propague y cause más daños.
- **Contención de corto plazo**: Aislar los sistemas afectados de la red (ej. desconectar el puerto del switch, desactivar la interfaz de red).
- **Contención de largo plazo**: Aplicar parches temporales, cambiar credenciales comprometidas y bloquear IPs/dominios de C2.

### 4. Erradicación (Eradication)
Eliminar la causa raíz del incidente.
- Identificación de todas las puertas traseras (backdoors) y cuentas creadas por el atacante.
- Limpieza de malware y eliminación de artefactos persistentes (registros, tareas programadas).

### 5. Recuperación (Recovery)
Restauración de los sistemas a su estado operativo normal.
- Restauración desde copias de seguridad (backups) verificadas.
- Monitorización intensiva para detectar si el atacante intenta reingresar.

### 6. Lecciones Aprendidas (Lessons Learned)
Revisión post-incidente para mejorar el proceso futuro.
- Documentación detallada de lo sucedido (timeline), qué funcionó bien y qué falló.
- Actualización de los planes de IR basados en la experiencia real.

## Herramientas de Apoyo
- **SIEM (Splunk, ELK)** — Visualización de logs y detección de patrones de ataque.
- **EDR (CrowdStrike, SentinelOne)** — Respuesta rápida en los endpoints para contención inmediata.
- **TheHive** — Plataforma de gestión de incidentes (SOAR) para coordinar la respuesta.
- **YARA** — Utilizado para buscar indicadores de compromiso (IoC) en toda la red durante la fase de erradicación.

## Ejemplo de Respuesta Inmediata (Contención)
```bash
# Aislar un host sospechoso en la red mediante reglas de firewall local (iptables)
iptables -A INPUT -s <IP_sospechosa> -j DROP
iptables -A OUTPUT -d <IP_sospechosa> -j DROP

# Deshabilitar un usuario comprometido en Active Directory (PowerShell)
Disable-ADAccount -Identity "usuario_comprometido"
```

## Referencias
- SANS Institute. (s.f.). *Incident Management and Response*. https://www.sans.org/incident-response/
- Luttgens, J., Pepe, M., & Hollebeek, K. (2014). *Incident Response & Computer Forensics* (3rd ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). *Incident Response Plan*. https://attack.mitre.org/resources/incident-response-plan/
- Notas del proyecto: notas-md/HNotes/HNotes/General/Network Analysis/Network Analysis.md
