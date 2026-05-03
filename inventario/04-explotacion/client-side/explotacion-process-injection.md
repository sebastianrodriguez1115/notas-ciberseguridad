---
title: Process Injection y Evasión
slug: explotacion-process-injection
aliases: [Process Injection y Evasión]
fase: [Explotación]
plataforma: Windows
dificultad: Avanzada
mitre: [T1055, T1055.012]
related: []
learning_refs: []
---

# Process Injection y Evasión

## Descripción
La inyección de procesos es una técnica de ejecución de código que consiste en ejecutar código arbitrario en el espacio de direcciones de un proceso legítimo activo. Esto permite a los atacantes ocultar su actividad, evadir defensas basadas en host (como antivirus o EDR) y heredar los privilegios o el acceso a la red del proceso víctima. Técnicas comunes incluyen Process Hollowing (reemplazar la imagen de un proceso suspendido) y DLL Injection (forzar a un proceso a cargar una biblioteca maliciosa).

## Herramientas
- **Donut** — generador de shellcode posicionalmente independiente a partir de binarios .NET, DLLs o EXEs.
- **Process Hacker** — para visualizar hilos inyectados y memoria manipulada en tiempo real.
- **msfvenom** (`-f raw`) — para generar los payloads iniciales que serán inyectados.
- **Cobalt Strike** (Beacon) — framework avanzado que utiliza diversos métodos de inyección de procesos de forma nativa.

## Comandos / Ejemplos

### Generación de Shellcode con Donut
```bash
# Convertir un ejecutable .NET en shellcode inyectable
./donut -i mimikatz.exe -o payload.bin
# El shellcode resultante puede ser inyectado usando un cargador personalizado
```

### DLL Injection vía PowerShell
```powershell
# Ejemplo conceptual de carga de DLL en un proceso remoto (PID 1234)
$Proc = [System.Diagnostics.Process]::GetProcessById(1234)
$DllPath = "C:\temp\malicious.dll"
# Se utilizan llamadas a la API de Windows (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread)
```

### Identificación de Process Hollowing
```bash
# Un indicio claro es un proceso cuyo ejecutable en disco difiere de su imagen en memoria
# o hilos cuya dirección base no corresponde a ningún módulo cargado
# Herramientas como PE-Sieve automatizan esta detección.
```

## Contramedidas
- Implementar soluciones EDR (Endpoint Detection and Response) que monitoreen llamadas sospechosas a la API de Windows (`CreateRemoteThread`, `WriteProcessMemory`).
- Habilitar el Attack Surface Reduction (ASR) de Microsoft Defender.
- Restringir privilegios de usuario para evitar que procesos no administrativos interactúen con otros procesos.
- Utilizar Device Guard para permitir solo la ejecución de binarios y bibliotecas firmadas.

## Referencias
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- MITRE Corporation. (2024). ATT&CK Technique T1055: Process Injection. https://attack.mitre.org/techniques/T1055/
