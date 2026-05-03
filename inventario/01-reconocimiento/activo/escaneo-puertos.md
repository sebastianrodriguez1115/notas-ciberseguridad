# Escaneo de Puertos

## Descripción
Técnica fundamental del reconocimiento activo que consiste en descubrir puertos abiertos y servicios en ejecución en los hosts objetivo. Mediante el envío de paquetes TCP o UDP a diferentes puertos, se determina cuales están abiertos (escuchando), cerrados o filtrados. El resultado define la superficie de ataque disponible y guía las fases posteriores de enumeración y explotación. Según *Mastering Kali Linux*, el escaneo no solo busca puertos, sino que analiza el comportamiento del stack TCP/IP ante respuestas no estándar para evadir firewalls.

## Clasificación
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: T1046 (Network Service Discovery)
- **Plataforma**: Multi
- **Dificultad**: Básica

## Herramientas
- **nmap** — Escáner de puertos por excelencia con múltiples técnicas de escaneo (SYN, Connect, UDP, FIN, XMAS)
- **masscan** — Escáner de puertos extremadamente rápido, capaz de escanear todo Internet en minutos
- **rustscan** — Escáner de puertos rápido escrito en Rust que complementa nmap con velocidad superior
- **zmap** — Similar a masscan, optimizado para escaneos de red a gran escala (capa de internet)

## Comandos / Ejemplos

### TCP SYN scan (stealth)
```bash
nmap -sS -p- 192.168.1.10
```
Escaneo sigiloso que envía SYN y analiza la respuesta sin completar el three-way handshake. Requiere privilegios root. Escanea los 65535 puertos.

### Escaneos Especializados (FIN, NULL, XMAS)
```bash
nmap -sF 192.168.1.10  # FIN scan
nmap -sN 192.168.1.10  # NULL scan
nmap -sX 192.168.1.10  # Xmas scan (flags FIN, PSH, URG)
```
*Nota técnica*: Estos escaneos son útiles para evadir firewalls stateless e IDS. Funcionan contra sistemas que siguen estrictamente el RFC 793 (la mayoría de sistemas Unix/Linux). **No funcionan contra sistemas Windows**, ya que estos responden con RST ante cualquier paquete no esperado.

### Evasión de IDS/Firewall (Técnicas de los libros)
```bash
nmap -f 192.168.1.10         # Fragmentación de paquetes
nmap --mtu 24 192.168.1.10   # Especificar MTU (debe ser múltiplo de 8)
nmap -D RND:10 192.168.1.10  # Uso de 10 señuelos (Decoys) aleatorios
nmap --source-port 53 192.168.1.10 # Falsear el puerto de origen (ej: DNS)
```
La fragmentación divide el header TCP en varios paquetes para que los filtros de paquetes simples no puedan inspeccionarlo completamente.

### TCP Idle Scan (Escaneo anónimo)
```bash
nmap -sI zombie_host:port target_host
```
Permite escanear un objetivo usando un host "zombie" (que tenga un IP ID predecible) para que el tráfico parezca provenir del zombie y no de nuestra IP.

## Contramedidas
- **Reglas de firewall**: Configurar firewalls para permitir solo tráfico a puertos necesarios y denegar el resto
- **Port knocking**: Implementar secuencias de conexión requeridas antes de abrir un puerto
- **IDS/IPS**: Configurar firmas de detección para patrones de escaneo de puertos (SYN scan, FIN scan, XMAS scan)
- **Rate limiting**: Limitar la cantidad de conexiones nuevas por segundo desde una misma IP
- **Cerrar puertos innecesarios**: Deshabilitar servicios que no se utilicen para reducir la superficie de ataque
- **Análisis de IP ID**: Mitigar escaneos Idle scan mediante la generación aleatoria de IDs de fragmentación IP

## Referencias
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- Kim, P. (2018). *The Hacker Playbook 3: Practical Guide to Penetration Testing*. Secure Planet.
- Hertzog, R., O'Gorman, J., & Aharoni, M. (2017). *Kali Linux Revealed*. OffSec Press.
- MITRE Corporation. (2024). ATT&CK Technique T1046: Network Service Discovery. https://attack.mitre.org/techniques/T1046/
