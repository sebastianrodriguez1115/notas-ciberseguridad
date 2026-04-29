# Sistemas: Arquitectura y Permisos en Linux

## Descripción
Linux es el sistema operativo predominante en servidores y entornos de nube. Para un pentester, es crucial comprender su estructura jerárquica de archivos, el funcionamiento del kernel, la gestión de procesos y el modelo de seguridad basado en permisos. Este conocimiento es la base para las técnicas de escalada de privilegios y persistencia.

## Clasificación
- **Fase**: Fundamentos
- **MITRE ATT&CK**: N/A (Concepto Base)
- **Plataforma**: Linux
- **Dificultad**: Básica

## Estructura Jerárquica de Archivos (FHS)

| Directorio | Descripción | Relevancia en Pentest |
| :--- | :--- | :--- |
| `/bin` / `/sbin` | Binarios esenciales del sistema. | Enumeración de herramientas disponibles. |
| `/etc` | Archivos de configuración. | `/etc/passwd`, `/etc/shadow` (credenciales). |
| `/home` | Directorios personales de los usuarios. | Archivos de configuración local (`.bash_history`, `.ssh`). |
| `/root` | Directorio personal del superusuario. | Objetivo final de la escalada de privilegios. |
| `/tmp` / `/dev/shm` | Archivos temporales (en disco y RAM). | Lugar para descargar exploits y herramientas. |
| `/proc` / `/sys` | Sistemas de archivos virtuales (kernel). | Información de procesos y hardware en tiempo real. |
| `/var/log` | Registros del sistema y servicios. | Identificación de actividades y borrado de huellas. |

## Modelo de Permisos Unix

Los permisos se dividen en tres categorías: **Usuario (u)**, **Grupo (g)** y **Otros (o)**.
Los tipos de acceso son: **Lectura (r=4)**, **Escritura (w=2)** y **Ejecución (x=1)**.

### Notación Simbólica y Octal
- `rwxr-xr-x` = 755 (El dueño tiene todo, el grupo y otros solo leen y ejecutan).
- `rw-r-----` = 640 (El dueño lee/escribe, el grupo lee, otros nada).

### Permisos Especiales
- **SUID (Set User ID)**: Ejecuta el archivo con los privilegios del dueño. Representado por una `s` en el permiso del dueño (ej. `rwsr-xr-x`). Es una vía común de escalada de privilegios.
- **SGID (Set Group ID)**: Ejecuta el archivo con los privilegios del grupo.
- **Sticky Bit**: Solo el dueño del archivo puede borrarlo, incluso si otros tienen permisos de escritura en el directorio (ej. `/tmp`).

## Comandos Esenciales de Gestión

### Visualizar permisos y archivos
```bash
ls -la /etc/passwd # Ver dueño, grupo y permisos detallados
stat /etc/shadow   # Ver información detallada de tiempos y permisos
```

### Cambiar dueños y permisos
```bash
# Cambiar dueño y grupo
sudo chown root:root archivo.txt
# Cambiar permisos (modo octal)
chmod 600 archivo_sensible.txt
```

### Gestión de Procesos
```bash
ps aux             # Listar todos los procesos del sistema
top / htop         # Monitorizar procesos en tiempo real
kill -9 <PID>      # Forzar la finalización de un proceso
```

## Referencias
- OccupyTheWeb. (2018). *Linux Basics for Hackers*. No Starch Press.
- Shotts, W. (2019). *The Linux Command Line: A Complete Introduction*. No Starch Press.
