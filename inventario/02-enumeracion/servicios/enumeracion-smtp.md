# Enumeración SMTP (Simple Mail Transfer Protocol)

## Descripción
SMTP (Simple Mail Transfer Protocol) es el protocolo estándar para envío de correo electrónico, operando en los puertos 25/tcp (relay), 465/tcp (SMTPS) y 587/tcp (submission). La enumeración SMTP permite identificar la versión del servidor de correo, verificar la existencia de usuarios mediante los comandos VRFY, EXPN y RCPT TO, y descubrir configuraciones inseguras como open relay. La enumeración de usuarios SMTP es especialmente valiosa porque permite construir una lista de cuentas válidas del sistema sin autenticación, que luego puede usarse para ataques de fuerza bruta contra otros servicios (SSH, SMB, RDP). Los servidores mal configurados que permiten open relay también pueden usarse para enviar correos de phishing.

## Clasificación
- **Fase**: Enumeración
- **MITRE ATT&CK**: T1589.002 (Gather Victim Identity Information: Email Addresses) — enumeración de usuarios; T1046 (Network Service Discovery) — descubrimiento del servicio
- **Plataforma**: Multi
- **Dificultad**: Básica

## Herramientas
- **nmap** (`smtp-commands`, `smtp-enum-users`, `smtp-open-relay`, `smtp-vuln-cve2010-4344`) — enumeración vía NSE
- **smtp-user-enum** — herramienta dedicada a enumeración de usuarios vía VRFY, EXPN y RCPT TO
- **telnet / netcat** — interacción manual con el protocolo SMTP
- **Metasploit** (`smtp_enum`, `smtp_version`) — enumeración automatizada de usuarios y versión
- **swaks** — navaja suiza para testing SMTP (Swiss Army Knife for SMTP)

## Comandos / Ejemplos

### Enumeración con Nmap NSE
```bash
# Detectar version del servidor SMTP
nmap -sV -p 25 <target>

# Enumerar comandos SMTP soportados (EHLO response)
nmap -p 25 --script smtp-commands <target>
# Resultado: VRFY, EXPN, ETRN, DSN, SIZE, HELP — indica que comandos acepta

# Enumeración de usuarios vía RCPT TO
nmap -p 25 --script smtp-enum-users \
  --script-args smtp-enum-users.methods={VRFY,EXPN,RCPT} <target>

# Verificar si el servidor es open relay
nmap -p 25 --script smtp-open-relay <target>
# Resultado: "Server is an open relay" si permite reenvio sin autenticacion

# Detectar vulnerabilidad Exim (CVE-2010-4344)
nmap -p 25 --script smtp-vuln-cve2010-4344 <target>
```

### Enumeración manual con telnet/netcat
```bash
# Conectar al servidor SMTP
nc -nv <target> 25

# Dentro de la sesion SMTP:
EHLO attacker.com          # Saludo extendido: revela comandos soportados y configuracion
VRFY root                  # Verificar si el usuario 'root' existe
VRFY admin                 # Verificar si el usuario 'admin' existe
EXPN postmaster            # Expandir alias: revela los destinatarios reales
RCPT TO:<admin@domain.com> # Verificar usuario via destinatario (requiere MAIL FROM previo)

# Flujo completo para RCPT TO:
MAIL FROM:<test@attacker.com>
RCPT TO:<admin@domain.com>      # 250 OK = usuario existe
RCPT TO:<noexiste@domain.com>   # 550 User unknown = no existe
```

**Códigos de respuesta clave:**
| Código | Significado |
|--------|-------------|
| 250 | OK — usuario existe / acción completada |
| 251 | Usuario no local, se reenviará |
| 252 | No se puede verificar, pero se intentará entregar |
| 550 | Usuario no existe / mailbox no disponible |
| 553 | Nombre de mailbox no permitido |

### Enumeración con smtp-user-enum
```bash
# Enumeración vía VRFY (método por defecto)
smtp-user-enum -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t <target>

# Enumeración vía EXPN
smtp-user-enum -M EXPN -U /usr/share/wordlists/metasploit/unix_users.txt -t <target>

# Enumeración vía RCPT TO
smtp-user-enum -M RCPT -U /usr/share/wordlists/metasploit/unix_users.txt -t <target>

# Especificar puerto no estándar
smtp-user-enum -M VRFY -U users.txt -t <target> -p 587
```

### Enumeración con Metasploit
```bash
# Detectar version del servidor SMTP
use auxiliary/scanner/smtp/smtp_version
set RHOSTS <target>
run
# Resultado: version del MTA (Postfix, Sendmail, Exim, hMailServer, etc.)

# Enumeración de usuarios
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS <target>
set USER_FILE /usr/share/wordlists/metasploit/unix_users.txt
run
# Resultado: lista de usuarios validos en el sistema
```

### Testing con swaks
```bash
# Verificar conectividad y version
swaks --to test@domain.com --server <target>

# Probar open relay
swaks --to externo@gmail.com --from falso@domain.com --server <target>

# Probar autenticación
swaks --to user@domain.com --server <target> --auth LOGIN --auth-user admin --auth-password pass
```

## Contramedidas
- Deshabilitar los comandos VRFY y EXPN en la configuración del servidor SMTP
- Configurar RCPT TO para no revelar si un usuario existe (respuesta genérica para todos los casos)
- No permitir open relay: restringir el reenvío a dominios y redes autorizadas
- Implementar rate limiting para prevenir enumeración masiva de usuarios
- Usar autenticación SMTP (SMTP AUTH) en los puertos de submission (587)
- Habilitar STARTTLS o usar SMTPS (465) para cifrar comunicaciones
- Implementar SPF, DKIM y DMARC para prevenir spoofing de correos

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Hertzog, R., & O'Gorman, J. (2017). *Kali Linux Revealed*. Offensive Security.
- MITRE Corporation. (2024). ATT&CK Technique T1589.002: Gather Victim Identity Information: Email Addresses. https://attack.mitre.org/techniques/T1589/002/
- MITRE Corporation. (2024). ATT&CK Technique T1046: Network Service Discovery. https://attack.mitre.org/techniques/T1046/
