# Modelo OSI y Protocolos TCP/IP

## Descripción
El Modelo OSI (Open Systems Interconnection) es un marco conceptual de siete capas que estandariza las funciones de un sistema de telecomunicaciones. Comprender este modelo y su implementación práctica en el stack TCP/IP es fundamental para el pentesting, ya que permite identificar en qué nivel ocurre una comunicación y cómo manipularla (ej. ataques de Capa 2 como ARP Spoofing vs ataques de Capa 7 como Inyección SQL).

## Clasificación
- **Fase**: Fundamentos
- **MITRE ATT&CK**: N/A (Concepto Base)
- **Plataforma**: Red
- **Dificultad**: Básica

## Capas del Modelo OSI vs TCP/IP

| Capa OSI | Nombre | Función Principal | Protocolos Comunes | Unidad de Datos (PDU) |
| :--- | :--- | :--- | :--- | :--- |
| 7 | Aplicación | Interfaz de usuario y servicios de red. | HTTP, FTP, SSH, DNS | Datos |
| 6 | Presentación | Formateo y cifrado de datos. | SSL/TLS, JPEG, ASCII | Datos |
| 5 | Sesión | Establecimiento y gestión de diálogos. | NetBIOS, RPC | Datos |
| 4 | Transporte | Entrega extremo a extremo y control de flujo. | TCP, UDP | Segmento (TCP) / Datagrama (UDP) |
| 3 | Red | Direccionamiento lógico y enrutamiento. | IP, ICMP, IPsec | Paquete |
| 2 | Enlace de Datos | Direccionamiento físico y acceso al medio. | Ethernet, ARP, Wi-Fi | Trama (Frame) |
| 1 | Física | Transmisión binaria y medios físicos. | Cable, Radiofrecuencia | Bits |

## Protocolos Críticos para el Pentesting

### TCP (Transmission Control Protocol)
Protocolo orientado a conexión que garantiza la entrega de datos.
- **Three-Way Handshake**: 
    1. `SYN` (Cliente -> Servidor)
    2. `SYN-ACK` (Servidor -> Cliente)
    3. `ACK` (Cliente -> Servidor)
- **Importancia**: El escaneo de puertos `nmap -sT` completa este proceso, mientras que `-sS` lo deja a medias (Stealth Scan).

### UDP (User Datagram Protocol)
Protocolo no orientado a conexión, más rápido pero sin garantía de entrega.
- **Importancia**: Utilizado en servicios como DNS (53), SNMP (161) y DHCP. Los escaneos UDP son más lentos y difíciles de validar.

### IP (Internet Protocol)
Encargado del direccionamiento de los paquetes.
- **IPv4**: Direcciones de 32 bits (ej. 192.168.1.1).
- **Subnetting**: División de redes usando máscaras (ej. /24 para 254 hosts).

## Comandos de Diagnóstico (Linux/Windows)

### Ver configuración de red
```bash
# Linux
ip addr show  # O 'ifconfig' (deprecado)
# Windows
ipconfig /all
```

### Verificar conectividad y rutas
```bash
# Probar latencia y estado del host
ping <IP_objetivo>
# Ver la ruta que siguen los paquetes
traceroute <IP_objetivo> # Linux
tracert <IP_objetivo>    # Windows
```

### Ver conexiones activas
```bash
# Listar puertos abiertos y conexiones establecidas
netstat -tunlp # Linux
netstat -ano   # Windows
```

## Referencias
- Lammle, T. (2016). *CompTIA Network+ Study Guide*. Sybex.
- Odom, W. (2020). *CCNA 200-301 Official Cert Guide*. Cisco Press.
- Notas del proyecto: notas-md/HNotes/HNotes/General/OSI.md
