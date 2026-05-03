# Fingerprinting de OS y Servicios

## Descripción
Técnica que permite determinar el sistema operativo y las versiones de servicios que se ejecutan en los hosts objetivo mediante sondeo activo. Según *Mastering Kali Linux*, el fingerprinting no solo analiza banners, sino que estudia el comportamiento del stack TCP/IP ante paquetes no estándar (probes). Parametros como el valor inicial del **TTL** (Time To Live) y el **TCP Window Size** son fundamentales para la identificación.

## Clasificación
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: T1592.002 (Gather Victim Host Information: Software) / T1046 (Network Service Discovery)
- **Plataforma**: Multi
- **Dificultad**: Intermedia

## Herramientas
- **nmap** — El estándar con su base de datos de firmas `nmap-os-db`
- **netcat (nc)** — Captura manual de banners
- **p0f** — Fingerprinting de OS de forma pasiva mediante el análisis del tráfico de red
- **nmap -sV --versión-all** — Intensidad máxima de probes para servicios en puertos no estándar

## Comandos / Ejemplos

### Análisis del Valor TTL (Análisis manual de stack)
- **TTL = 64**: Usualmente sistemas Linux/Unix.
- **TTL = 128**: Usualmente sistemas Windows.
- **TTL = 255**: Usualmente dispositivos de red (Cisco/Juniper).
```bash
ping -c 1 192.168.1.10  # Observar el campo ttl en la respuesta
```

### TCP Window Size y Fingerprinting
```bash
nmap -O 192.168.1.10
```
Nmap envía 8 probes (TCP, UDP, ICMP) y analiza 15 campos de respuesta, incluyendo Window Size, opciones TCP y el orden de los flags, para generar una firma que compara con su base de datos.

### Fingerprinting Pasivo con p0f
```bash
p0f -i eth0
```
Permite identificar sistemas operativos de clientes y servidores analizando el tráfico que pasa por la interfaz de red sin interactuar con ellos.

### Banner Grabbing Avanzado
```bash
nmap -sV --versión-intensity 9 192.168.1.10
```
Aumenta la intensidad de los probes para intentar identificar servicios altamente personalizados o protegidos.

## Contramedidas
- **Modificar TTL**: Ajustar el valor de TTL de salida para confundir herramientas de fingerprinting.
- **Normalizar Respuestas TCP**: Utilizar firewalls que normalicen los parametros TCP Window Size.
- **Modificar/Eliminar Banners**: Configurar servicios para no revelar su versión.
- **Uso de WAF e IPS**: Detectar y bloquear probes de nmap dirigidos a la identificación de OS.

## Referencias
- Allen, L. (2018). *Mastering Kali Linux for Advanced Penetration Testing* (2nd ed.). Packt Publishing.
- Kim, P. (2018). *The Hacker Playbook 3: Practical Guide to Penetration Testing*. Secure Planet.
- MITRE Corporation. (2024). ATT&CK Technique T1592.002: Gather Victim Host Information: Software. https://attack.mitre.org/techniques/T1592/002/
