# Escaneo de Puertos

## Descripcion
Tecnica fundamental del reconocimiento activo que consiste en descubrir puertos abiertos y servicios en ejecucion en los hosts objetivo. Mediante el envio de paquetes TCP o UDP a diferentes puertos, se determina cuales estan abiertos (escuchando), cerrados o filtrados. El resultado define la superficie de ataque disponible y guia las fases posteriores de enumeracion y explotacion. Segun *Mastering Kali Linux*, el escaneo no solo busca puertos, sino que analiza el comportamiento del stack TCP/IP ante respuestas no estandar para evadir firewalls.

## Clasificacion
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: T1046 (Network Service Discovery)
- **Plataforma**: Multi
- **Dificultad**: Basica

## Herramientas
- **nmap** — Escaner de puertos por excelencia con multiples tecnicas de escaneo (SYN, Connect, UDP, FIN, XMAS)
- **masscan** — Escaner de puertos extremadamente rapido, capaz de escanear todo Internet en minutos
- **rustscan** — Escaner de puertos rapido escrito en Rust que complementa nmap con velocidad superior
- **zmap** — Similar a masscan, optimizado para escaneos de red a gran escala (capa de internet)

## Comandos / Ejemplos

### TCP SYN scan (stealth)
```bash
nmap -sS -p- 192.168.1.10
```
Escaneo sigiloso que envia SYN y analiza la respuesta sin completar el three-way handshake. Requiere privilegios root. Escanea los 65535 puertos.

### Escaneos Especializados (FIN, NULL, XMAS)
```bash
nmap -sF 192.168.1.10  # FIN scan
nmap -sN 192.168.1.10  # NULL scan
nmap -sX 192.168.1.10  # Xmas scan (flags FIN, PSH, URG)
```
*Nota técnica*: Estos escaneos son utiles para evadir firewalls stateless e IDS. Funcionan contra sistemas que siguen estrictamente el RFC 793 (la mayoria de sistemas Unix/Linux). **No funcionan contra sistemas Windows**, ya que estos responden con RST ante cualquier paquete no esperado.

### Evasion de IDS/Firewall (Tecnicas de los libros)
```bash
nmap -f 192.168.1.10         # Fragmentacion de paquetes
nmap --mtu 24 192.168.1.10   # Especificar MTU (debe ser multiplo de 8)
nmap -D RND:10 192.168.1.10  # Uso de 10 señuelos (Decoys) aleatorios
nmap --source-port 53 192.168.1.10 # Falsear el puerto de origen (ej: DNS)
```
La fragmentacion divide el header TCP en varios paquetes para que los filtros de paquetes simples no puedan inspeccionarlo completamente.

### TCP Idle Scan (Escaneo anonimo)
```bash
nmap -sI zombie_host:port target_host
```
Permite escanear un objetivo usando un host "zombie" (que tenga un IP ID predecible) para que el trafico parezca provenir del zombie y no de nuestra IP.

## Contramedidas
- **Reglas de firewall**: Configurar firewalls para permitir solo trafico a puertos necesarios y denegar el resto
- **Port knocking**: Implementar secuencias de conexion requeridas antes de abrir un puerto
- **IDS/IPS**: Configurar firmas de deteccion para patrones de escaneo de puertos (SYN scan, FIN scan, XMAS scan)
- **Rate limiting**: Limitar la cantidad de conexiones nuevas por segundo desde una misma IP
- **Cerrar puertos innecesarios**: Deshabilitar servicios que no se utilicen para reducir la superficie de ataque
- **Analisis de IP ID**: Mitigar escaneos Idle scan mediante la generacion aleatoria de IDs de fragmentacion IP

## Referencias
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- Kim, P. (2018). *The Hacker Playbook 3: Practical Guide to Penetration Testing*. Secure Planet.
- Hertzog, R., O'Gorman, J., & Aharoni, M. (2017). *Kali Linux Revealed*. OffSec Press.
- Notas del proyecto: notas-md/HNotes/Recon/Active Enumeration/nmap.md
- Notas del proyecto: notas-md/INE Courses/Assessment Methodologies Footprinting & Scanning.md
- MITRE Corporation. (2024). ATT&CK Technique T1046: Network Service Discovery. https://attack.mitre.org/techniques/T1046/
