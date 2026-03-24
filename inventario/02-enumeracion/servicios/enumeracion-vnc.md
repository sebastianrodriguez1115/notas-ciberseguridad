# Enumeración VNC (Virtual Network Computing) (Puerto 5900+)

## Descripción
VNC es un sistema de compartición de escritorio remoto que utiliza el protocolo RFB (Remote Frame Buffer). La enumeración de VNC se centra en identificar la versión del servidor, los métodos de autenticación soportados y buscar contraseñas débiles o por defecto. A diferencia de RDP, muchas implementaciones de VNC permiten el acceso compartido y, a veces, operan sin cifrado robusto.

## Clasificación
- **Fase**: Enumeración
- **MITRE ATT&CK**: T1021.005 (Remote Services: VNC)
- **Plataforma**: Multi
- **Dificultad**: Básica

## Herramientas
- **nmap** — scripts NSE especializados (vnc-info, vnc-brute)
- **vncviewer** — cliente oficial para conexión visual
- **vnc-crack** — herramienta para crackear contraseñas VNC offline
- **Metasploit** — módulos auxiliares para detección y fuerza bruta

## Comandos / Ejemplos

### Escaneo con Nmap
```bash
# Obtener información básica y métodos de autenticación
nmap -p 5900 -sV --script vnc-info 10.10.10.10

# Fuerza bruta de contraseñas (VNC suele tener solo contraseña, sin usuario)
nmap -p 5900 --script vnc-brute --script-args passdb=/usr/share/wordlists/seclists/Passwords/Common-Credentials/top-100-common-passwords.txt 10.10.10.10
```

### Identificación de versiones y puertos comunes
VNC suele empezar en el puerto 5900 (display 0). El puerto 5901 es el display 1, y así sucesivamente.
```bash
# Escanear rango de puertos comunes para VNC
nmap -p 5900-5910 -sV 10.10.10.10
```

### Fuerza bruta con Metasploit
```bash
msfconsole -q
use auxiliary/scanner/vnc/vnc_login
set RHOSTS 10.10.10.10
set PASS_FILE /usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt
run
```

### Conexión visual si se tiene la contraseña
```bash
# Conectar al servidor VNC
vncviewer 10.10.10.10:0
```

### Decodificación de contraseñas VNC
Si se encuentra un hash de VNC (ej: en el registro de Windows), se puede usar `vncpwd` o el decodificador de Metasploit, ya que VNC utiliza DES con una clave fija:
```bash
# Usando vncpwd (si se tiene el archivo de configuración o el hash)
vncpwd /path/to/passwd

# En Metasploit irb
msfconsole -q
irb
>> require 'rex'
>> Rex::Proto::RFB::Cipher.decrypt(["<hash_hex>"].pack('H*'), "program")
```

## Contramedidas
- **Deshabilitar VNC** si no es estrictamente necesario o usar protocolos más seguros como SSH con port forwarding.
- **Utilizar contraseñas robustas** y diferentes a las del sistema operativo.
- **Implementar cifrado** mediante el uso de túneles SSH o TLS (muchas versiones antiguas de VNC envían datos en claro).
- **Restringir el acceso por IP** utilizando firewalls.
- **Activar bloqueos de cuenta** tras varios intentos fallidos de autenticación.

## Referencias
- RealVNC Documentation. (2024). Security and Authentication. https://www.realvnc.com/docs/
- HackTricks. (2024). 5900 - Pentesting VNC. https://book.hacktricks.xyz/network-services-pentesting/pentesting-vnc
- SecLists: /usr/share/wordlists/seclists/Passwords/Common-Credentials/10-million-password-list-top-100.txt
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
