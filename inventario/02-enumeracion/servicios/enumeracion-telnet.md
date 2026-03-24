# Enumeración Telnet (Puerto 23)

## Descripción
Telnet es un protocolo heredado utilizado para acceder a terminales remotos. Carece de cualquier tipo de cifrado, enviando tanto credenciales como datos en texto claro, lo que lo hace altamente vulnerable a ataques de intercepción (Sniffing). La enumeración de Telnet se centra en obtener el banner del servicio, descubrir el sistema operativo subyacente e intentar el acceso mediante credenciales por defecto o ataques de fuerza bruta.

## Clasificación
- **Fase**: Enumeración
- **MITRE ATT&CK**: 
    - T1046 (Network Service Discovery)
    - T1021 (Remote Services)
- **Plataforma**: Multi
- **Dificultad**: Básica

## Herramientas
- **telnet** — cliente interactivo básico
- **nc** (netcat) — para banner grabbing y escaneo rápido
- **nmap** — scripts NSE especializados (telnet-brute, telnet-encryption)
- **Metasploit** — módulos para escaneo y fuerza bruta de credenciales

## Comandos / Ejemplos

### Banner Grabbing
```bash
# Conexión directa para ver el banner
telnet 10.10.10.10 23

# Usando nc (netcat)
nc -vn 10.10.10.10 23
```

### Escaneo con Nmap
```bash
# Identificar servicio y versiones
nmap -p 23 -sV 10.10.10.10

# Fuerza bruta de credenciales
nmap -p 23 --script telnet-brute --script-args userdb=users.txt,passdb=pass.txt 10.10.10.10

# Listar opciones soportadas por el servidor Telnet
nmap -p 23 --script telnet-ntlm-info 10.10.10.10
```

### Fuerza bruta con Metasploit
```bash
msfconsole -q
use auxiliary/scanner/telnet/telnet_login
set RHOSTS 10.10.10.10
set USER_FILE /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt
set PASS_FILE /usr/share/wordlists/seclists/Passwords/Common-Credentials/top-100-common-passwords.txt
run
```

### Sniffing de credenciales (Si se está en la misma red)
Si se tiene acceso a la red (Man-in-the-Middle o puerto espejo), se pueden extraer las credenciales en claro:
```bash
# Usando tcpdump para capturar tráfico Telnet
tcpdump -i eth0 port 23 -A | grep -iE "user|pass|login"
```

## Contramedidas
- **Reemplazar Telnet por SSH** (Secure Shell) inmediatamente en todos los sistemas y dispositivos de red.
- **Deshabilitar el puerto 23** en firewalls perimetrales e internos.
- **Implementar autenticación fuerte** si Telnet es absolutamente necesario por razones de legado (aunque no es recomendable).
- **Usar VPN** o túneles cifrados si se debe acceder a servicios Telnet heredados a través de redes inseguras.
- **Cerrar sesiones inactivas** automáticamente tras un periodo de tiempo.

## Referencias
- IETF. (1983). RFC 854: Telnet Protocol Specification. https://datatracker.ietf.org/doc/html/rfc854
- HackTricks. (2024). 23 - Pentesting Telnet. https://book.hacktricks.xyz/network-services-pentesting/pentesting-telnet
- SecLists: /usr/share/wordlists/seclists/Passwords/Default-Credentials/telnet-betterdefaultpasslist.txt
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
