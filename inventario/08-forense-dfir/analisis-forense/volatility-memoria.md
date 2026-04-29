# Volatility: Análisis Forense de Memoria

## Descripción
El análisis de memoria RAM (Forensics in RAM) permite identificar actividades volátiles que no dejan rastro en el disco duro, como procesos en ejecución, conexiones de red activas, claves de cifrado, contraseñas en texto plano y código malicioso inyectado (Rootkits/Beacons). Volatility es el framework de código abierto líder en la industria para el análisis forense de volcados de memoria (dumps).

## Clasificación
- **Fase**: Forense y DFIR
- **MITRE ATT&CK**: T1055 (Process Injection); T1014 (Rootkit)
- **Plataforma**: Multi
- **Dificultad**: Avanzada

## Herramientas
- **Volatility 2.6 / 3** — Framework principal para el análisis de volcados de memoria.
- **FTK Imager** — Utilizado para realizar la adquisición física de la memoria RAM.
- **DumpIt / Magnet RAM Capture** — Herramientas ligeras para la captura rápida de memoria en sistemas Windows.

## Comandos / Ejemplos (Volatility 2.6)

### Identificación del Perfil del Sistema
Antes de analizar la memoria, se debe identificar el perfil del SO (SO, arquitectura, versión del kernel).
```bash
# Identificar perfil sugerido
vol.py -f memory_dump.raw imageinfo
```

### Enumeración de Procesos y Redes
```bash
# Listar procesos activos (pstree muestra jerarquía)
vol.py -f memory_dump.raw --profile=Win7SP1x64 pstree

# Listar conexiones de red abiertas
vol.py -f memory_dump.raw --profile=Win7SP1x64 netscan

# Buscar comandos ejecutados en la consola (CMD)
vol.py -f memory_dump.raw --profile=Win7SP1x64 cmdscan
```

### Detección de Malware e Inyecciones
```bash
# Malfind: Busca inyecciones de código sospechosas en el espacio de memoria de un proceso
vol.py -f memory_dump.raw --profile=Win7SP1x64 malfind -p <PID> -D /ruta/volcado/

# Volcar un proceso sospechoso para análisis estático
vol.py -f memory_dump.raw --profile=Win7SP1x64 procdump -p <PID> --dump-dir /ruta/
```

### Extracción de Credenciales
```bash
# Volcar hashes de contraseñas de la memoria del proceso LSASS
vol.py -f memory_dump.raw --profile=Win7SP1x64 hashdump
```

## Flujo de Trabajo Recomendado
1.  **Adquisición**: Capturar la memoria lo antes posible para evitar la pérdida de datos volátiles (Principio de Orden de Volatilidad).
2.  **Identificación**: Determinar el perfil correcto del sistema operativo.
3.  **Análisis de Procesos**: Buscar procesos con nombres sospechosos, sin procesos padre lógicos o con privilegios inusuales.
4.  **Análisis de Red**: Identificar conexiones a IPs externas sospechosas o puertos inusuales (ej. 4444, 8888).
5.  **Extracción**: Volcar los ejecutables sospechosos para realizar un análisis de malware más profundo.

## Referencias
- Ligh, M. H., Case, A., Levy, J., & Walters, B. (2014). *The Art of Memory Forensics*. John Wiley & Sons.
- Volatility Foundation. (s.f.). *Volatility Framework* [Software]. https://www.volatilityfoundation.org/
- MITRE Corporation. (2024). ATT&CK Technique T1055: Process Injection. https://attack.mitre.org/techniques/T1055/
