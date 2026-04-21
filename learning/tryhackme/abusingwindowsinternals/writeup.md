# Writeup: Abusing Windows Internals (TryHackMe)

## Introducción
Este room se enfoca en el abuso de componentes internos de Windows (procesos, DLLs y formato PE) para ejecutar código de manera sigilosa y evadir detecciones.

---

## Tarea 2: Shellcode Injection
La inyección de shellcode es la forma más básica de inyección de procesos. Consiste en insertar código malicioso en un proceso legítimo activo.

### Flujo de Trabajo (4 Pasos):
1. **OpenProcess**: Abrir el proceso objetivo con todos los derechos de acceso.
2. **VirtualAllocEx**: Asignar espacio de memoria en el proceso remoto.
3. **WriteProcessMemory**: Escribir el shellcode en el espacio asignado.
4. **CreateRemoteThread**: Ejecutar el shellcode creando un nuevo hilo en el proceso objetivo.

### Comandos Utilizados:
Para identificar procesos del usuario objetivo (`THM-Attacker`):
```powershell
Get-Process -IncludeUserName | Where-Object {$_.UserName -like "*THM-Attacker*"}
```

Ejecución del inyector (usando el PID de `explorer.exe` como ejemplo):
```powershell
.\shellcode-injector.exe 3276
```

---

## Tarea 3: Process Hollowing
Técnica que consiste en crear un proceso legítimo en estado suspendido, "vaciarlo" (un-mapping) de su código original y reemplazarlo por una imagen ejecutable (PE) maliciosa.

### Flujo de Trabajo (6 Pasos):
1. **CreateProcessA**: Crear proceso en estado `CREATE_SUSPENDED`.
2. **Obtención de Imagen**: Abrir el archivo malicioso (`CreateFileA`, `ReadFile`).
3. **Un-map**: Vaciar la memoria del proceso original (`ZwUnmapViewOfSection`).
4. **Relocalización**: Asignar memoria y escribir las secciones del PE malicioso (`VirtualAllocEx`, `WriteProcessMemory`).
5. **Set Context**: Cambiar el punto de entrada (EIP/RIP) del hilo al nuevo código (`SetThreadContext`).
6. **Resume**: Reanudar el hilo para ejecutar el malware (`ResumeThread`).

### Resolución y Flag:
El inyector `hollowing-injector.exe` requiere el PID de un proceso padre para robar el token y la ruta completa del proceso a suplantar.

**Comando Correcto:**
```powershell
.\hollowing-injector.exe <PID_EXPLORER> C:\Windows\System32\svchost.exe
```

**Nota sobre la Flag:** 
La flag de esta tarea es un mensaje que parece un error o un aviso de que no hay nada, pero es la flag real.
- **Flag**: `THM{7h3r35_n07h1n6_h3r3}`

---

## Tarea 4: Thread Execution Hijacking
Técnica que consiste en secuestrar un hilo existente de un proceso legítimo para redirigir su flujo de ejecución hacia nuestro código malicioso (shellcode). A diferencia de `CreateRemoteThread`, esta técnica es más sigilosa ya que no crea hilos nuevos.

### Flujo de Trabajo (10 Pasos):
1. **OpenProcess**: Abrir el proceso objetivo.
2. **VirtualAllocEx**: Asignar memoria para el shellcode.
3. **WriteProcessMemory**: Escribir el shellcode en la memoria asignada.
4. **Identify Thread ID**: Enumerar hilos del proceso (`CreateToolhelp32Snapshot`, `Thread32First/Next`).
5. **OpenThread**: Abrir el hilo objetivo.
6. **SuspendThread**: Pausar la ejecución del hilo.
7. **GetThreadContext**: Capturar el estado actual de los registros (incluyendo RIP/EIP).
8. **Update RIP**: Modificar el puntero de instrucción para que apunte a nuestro shellcode.
9. **SetThreadContext**: Aplicar los cambios al contexto del hilo.
10. **ResumeThread**: Reanudar la ejecución.

### Resolución y Flag:
Se debe identificar un PID que pertenezca al usuario `THM-Attacker` (por ejemplo, abriendo un `notepad.exe`).

**Comando:**
```powershell
.\thread-injector.exe <PID_NOTEPAD>
```

- **Flag**: `THM{w34p0n1z3d_53w1n6}`

---

## Tarea 5: DLL Injection
Técnica que consiste en forzar a un proceso legítimo a cargar una librería dinámica (DLL) maliciosa. A diferencia de la inyección de shellcode, aquí se inyecta la ruta de un archivo `.dll` y se utiliza la función `LoadLibrary` para ejecutarlo dentro del contexto del proceso objetivo.

### Flujo de Trabajo (5 Pasos):
1. **Locate Process**: Encontrar el PID del proceso objetivo (usando `CreateToolhelp32Snapshot`).
2. **OpenProcess**: Abrir el proceso objetivo con todos los derechos de acceso.
3. **VirtualAllocEx**: Asignar memoria en el proceso remoto, pero esta vez para almacenar la **ruta completa** de la DLL maliciosa.
4. **WriteProcessMemory**: Escribir la ruta de la DLL en el espacio asignado.
5. **Execute**: Obtener la dirección de `LoadLibraryA` (de `kernel32.dll`) y usar `CreateRemoteThread` para llamar a dicha función, pasando la dirección de la ruta inyectada como argumento.

### Resolución y Flag:
A diferencia de los inyectores anteriores, este utiliza el **nombre del proceso** (ej. `notepad.exe`) ya que incluye una función de búsqueda interna. Es fundamental usar la ruta completa de la DLL.

**Comando Correcto:**
```powershell
.\dll-injector.exe notepad.exe C:\Users\THM-Attacker\Desktop\Injectors\evil.dll
```

- **Flag**: `THM{n07_4_m4l1c10u5_dll}`

---

## Tarea 6: Memory Execution Alternatives
Existen métodos alternativos para ejecutar shellcode que evaden hooks de APIs comunes como `CreateRemoteThread`.

### 1. Invoking Function Pointers
Método evasivo que no usa APIs del sistema. Se basa en el casting de un bloque de memoria (donde reside el shellcode) a un puntero de función y su ejecución directa.
- **Limitación**: Solo funciona con memoria asignada localmente.
- **Línea clave**: `((void(*)())addressPointer)();`

### 2. Asynchronous Procedure Calls (APC)
Consiste en encolar una función maliciosa en un hilo legítimo mediante `QueueUserAPC`. La función se ejecuta cuando el hilo entra en un "alertable state" (ej. esperando con `Sleep` o `WaitForSingleObject`).
- **Flujo**: `VirtualAllocEx` -> `WriteProcessMemory` -> `QueueUserAPC` -> `ResumeThread`.

### Resolución y Flag:
En esta tarea se exploran las alternativas teóricas y prácticas de ejecución.

- **Respuesta 1 (Void Function Pointer en proceso remoto)**: `n` (Solo funciona localmente).
- **Flag**: `PENDIENTE_DE_TU_CONFIRMACION`

---

## Tarea 7: Case Study - TrickBot
Análisis basado en la investigación de [SentinelOne](https://www.sentinelone.com/labs/how-trickbot-malware-hooking-engine-targets-windows-10-browsers/). TrickBot es un malware bancario que utiliza **inyección reflectiva** y **hooking de navegador** para interceptar credenciales.

### Flujo de Inyección Reflectiva de TrickBot:
1. **OpenProcess**: Obtener handle del navegador (`chrome.exe`, `firefox.exe`, etc.).
2. **VirtualAllocEx**: Asignar memoria remota.
3. **WriteProcessMemory**: Copiar la función de hooking y el shellcode.
4. **FlushInstructionCache**: Asegurar que los cambios se confirmen en memoria.
5. **RemoteThread**: Ejecutar el código inyectado (usando `CreateRemoteThread` o `RtlCreateUserThread`).

### Técnica de Hooking (Inline Hooking):
TrickBot modifica la función original del sistema para redirigir el flujo hacia su propio código:
- Cambia permisos de memoria a `PAGE_EXECUTE_READWRITE` (`0x40`).
- Escribe un `JMP` (`0xE9`) hacia su función maliciosa.
- Restaura los permisos originales.

### Resolución y Flag:
En este caso de estudio se analiza el comportamiento real de TrickBot.

- **Respuesta 1 (Inyección reflectiva de TrickBot)**: `y` (TrickBot utiliza inyección reflectiva para ser más sigiloso).

---

## Próximos Pasos
- [x] Task 4: Thread Execution Hijacking
- [x] Task 5: DLL Injection
- [x] Task 6: Memory Execution Alternatives
- [x] Task 7: Case Study in Browser Injection and Hooking
- [x] Conclusión y Flag Final

.
