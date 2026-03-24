# Enumeración SNMP (Simple Network Management Protocol)

## Descripción
SNMP (Simple Network Management Protocol) es un protocolo de gestión de red que permite monitorear y configurar dispositivos de red (routers, switches, servidores, impresoras). Opera en los puertos 161/UDP (agente) y 162/UDP (traps). Las versiones SNMPv1 y SNMPv2c transmiten las community strings en texto plano, lo que las hace vulnerables a sniffing y brute force. Con la community string correcta (tipicamente "public" para lectura), se puede extraer una gran cantidad de información del sistema: interfaces de red, procesos, software instalado, puertos abiertos, usuarios y configuración.

## Clasificación
- **Fase**: Enumeración
- **MITRE ATT&CK**: T1046 (Network Service Discovery)
- **Plataforma**: Multi
- **Dificultad**: Básica

## Herramientas
- **onesixtyone** — fuerza bruta rapida de community strings SNMP
- **snmpwalk** — enumeración recursiva de todos los OIDs del agente
- **snmp-check** — enumeración amigable con salida organizada por categoria
- **snmpget** — consulta de un OID especifico
- **Metasploit** (`auxiliary/scanner/snmp/snmp_enum`) — enumeración automatizada

## Comandos / Ejemplos

### Descubrimiento y fuerza bruta de community strings
```bash
# Nmap - detectar SNMP activo
nmap -sU -p 161 <target>
nmap -sU -p 161 --script snmp-info <target>

# onesixtyone - brute force de community strings
onesixtyone -c /usr/share/doc/onesixtyone/dict.txt <target>
onesixtyone -c /usr/share/wordlists/metasploit/snmp_default_pass.txt <target>

# Community strings por defecto a probar: public, private, manager, cisco
```

### snmpwalk - enumeración completa
```bash
# Enumeracion completa del arbol MIB
snmpwalk -v 2c -c public <target>
snmpwalk -v 1  -c public <target>    # SNMPv1

# OIDs especificos de interes:
# Procesos en ejecucion
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.25.4.2.1.2

# Software instalado
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.25.6.3.1.2

# Puertos TCP abiertos
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.6.13.1.3

# Informacion del sistema (hostname, descripcion, uptime)
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.1

# Interfaces de red
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.2

# Usuarios del sistema
snmpwalk -v 2c -c public <target> 1.3.6.1.2.1.25.1.5.0
```

### snmp-check - salida amigable
```bash
snmp-check <target> -c public
snmp-check <target> -c public -v 2c
```

### Metasploit
```bash
use auxiliary/scanner/snmp/snmp_enum
set RHOSTS <target>
set COMMUNITY public
run

# Modulo para brute force de community strings
use auxiliary/scanner/snmp/snmp_login
set RHOSTS <target>
set PASS_FILE /usr/share/wordlists/metasploit/snmp_default_pass.txt
run
```

**OIDs mas importantes:**
| OID | Descripción |
|-----|-------------|
| 1.3.6.1.2.1.1 | Información del sistema (sysDescr, sysName) |
| 1.3.6.1.2.1.2 | Interfaces de red |
| 1.3.6.1.2.1.6.13.1.3 | Puertos TCP abiertos |
| 1.3.6.1.2.1.25.4.2.1.2 | Procesos en ejecución |
| 1.3.6.1.2.1.25.6.3.1.2 | Software instalado |
| 1.3.6.1.2.1.25.1.5.0 | Usuarios logueados |

## Contramedidas
- Usar SNMPv3 con autenticación (MD5/SHA) y cifrado (DES/AES) en lugar de v1/v2c
- Cambiar las community strings por defecto ("public", "private") por valores complejos
- Deshabilitar SNMP si no se necesita para gestión de red
- Restringir acceso SNMP por firewall a IPs de gestión autorizadas
- Filtrar trafico UDP 161 en el perimetro de red
- Monitorear intentos de acceso SNMP no autorizados en los logs del dispositivo

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1046: Network Service Discovery. https://attack.mitre.org/techniques/T1046/
- OWASP Foundation. (s.f.). *Testing for SNMP*. https://owasp.org/www-project-web-security-testing-guide/
