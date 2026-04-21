# Windows API para Hacking

## Descripción
La Windows API (Win32 API) es la interfaz nativa que permite a las aplicaciones interactuar con los componentes clave del sistema operativo Windows, como la memoria, los procesos y el hardware. En el ámbito del hacking y el desarrollo de malware, es fundamental para técnicas de inyección de procesos, evasión de defensas y persistencia. Comprender su nomenclatura y las constantes de gestión de memoria permite al atacante manipular el espacio de direcciones de procesos legítimos y evadir mecanismos de detección como EDR.

### Conceptos Clave
- **Handle (Manejador)**: Es un valor abstracto (un "ticket") que el sistema operativo entrega a una aplicación para que esta pueda referenciar un objeto interno (archivo, proceso, hilo, ventana) sin tener acceso directo a su dirección de memoria. Proporciona una capa de seguridad y abstracción.
- **Pseudo Handle**: Un valor especial (frecuentemente `-1`) que representa al proceso actual. Solo es válido dentro del contexto del propio proceso y no puede ser utilizado por otros procesos para referenciarlo. Para obtener un handle real y único, se suelen usar funciones como `OpenProcess` o `GetModuleHandle`.

## Clasificación
- **Fase**: Fundamentos
- **MITRE ATT&CK**: T1106 (Native API); T1055 (Process Injection)
- **Plataforma**: Windows
- **Dificultad**: Intermedia

## Herramientas
- **msfvenom** (`-f c`, `-f powershell`) — genera shellcode compatible con llamadas a la API de Windows.
- **Visual Studio / C++** — entorno principal para el desarrollo de loaders y exploits que invocan la Win32 API.
- **P/Invoke** (Platform Invoke) — tecnología que permite llamar a funciones de la API de Windows desde código gestionado como C# o PowerShell.
- **Process Hacker** — permite visualizar las regiones de memoria asignadas (`Commit`, `Reserve`) y sus protecciones.

## Comandos / Ejemplos

### Nomenclatura de Llamadas
Las funciones de la API a menudo tienen sufijos que indican su comportamiento:
- **A** (ANSI): Utiliza juegos de caracteres de 8 bits (ej. `MessageBoxA`).
- **W** (Wide/Unicode): Utiliza juegos de caracteres Unicode (ej. `MessageBoxW`).
- **Ex** (Extended): Versiones que ofrecen funcionalidad o parámetros adicionales (ej. `VirtualAllocEx`).

### Gestión de Memoria (`VirtualAlloc`)
Constantes críticas para la asignación de memoria durante la explotación:
- **MEM_COMMIT** (0x1000): Reserva memoria física en el archivo de paginación o RAM.
- **MEM_RESERVE** (0x2000): Reserva un rango del espacio de direcciones virtuales del proceso.
- **MEM_RESET** (0x00080000): Indica que el contenido de la memoria ya no es de interés para el sistema operativo.
- **MEM_RESET_UNDO** (0x1000000): Revierte un `MEM_RESET` previo si los datos aún no han sido descartados.

### Protecciones de Memoria (`flProtect`)
Valores comunes utilizados para definir permisos en regiones de memoria:
- **PAGE_NOACCESS** (0x01): Deshabilita todo el acceso a la región.
- **PAGE_READONLY** (0x02): Solo permite lectura.
- **PAGE_READWRITE** (0x04): Permite lectura y escritura (común para buffers de datos).
- **PAGE_EXECUTE_READWRITE** (0x40): Permite lectura, escritura y ejecución. Es la configuración más peligrosa y común en cargadores de shellcode.

### Ejemplo conceptual de asignación en C++
```cpp
// Reservar y asignar memoria con permisos de ejecución
LPVOID pMemory = VirtualAlloc(
    NULL,                   // El sistema elige la dirección
    1024,                   // Tamaño de la región
    MEM_COMMIT | MEM_RESERVE, // Tipo de asignación
    PAGE_EXECUTE_READWRITE  // Permisos (R/W/X)
);
```

## Contramedidas
- Implementar soluciones EDR que monitoreen llamadas sospechosas a la API (`VirtualAllocEx`, `WriteProcessMemory`).
- Utilizar **Arbitrary Code Guard (ACG)** para evitar la creación de nuevas regiones de memoria ejecutables o la modificación de las existentes a RWX.
- Habilitar **Control Flow Guard (CFG)** para detectar redirecciones de flujo de ejecución indirectas.

## Referencias
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
- Microsoft. (s.f.). *VirtualAlloc function (memoryapi.h)*. Windows API Documentation. https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
- MITRE Corporation. (2024). ATT&CK Technique T1106: Native API. https://attack.mitre.org/techniques/T1106/
- Notas del proyecto: learning/tryhackme/windowsapi/4_os_libraries.md
- Notas del proyecto: learning/tryhackme/windowsapi/5_api_call_structure.md
