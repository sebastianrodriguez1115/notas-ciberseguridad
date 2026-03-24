# Enumeración LDAP (Lightweight Directory Access Protocol)

## Descripción
LDAP (Lightweight Directory Access Protocol) es un protocolo de acceso a servicios de directorio que opera en el puerto 389/tcp (texto claro) y 636/tcp (LDAPS/SSL). Es el pilar de Active Directory en entornos Windows y se usa para almacenar información de usuarios, grupos, equipos, politicas y estructura organizativa. La enumeración LDAP permite extraer el esquema completo del directorio: usuarios y sus atributos (descripción, email, último login), grupos y membresias, unidades organizativas (OUs), politicas de contraseñas, cuentas deshabilitadas, SPNs (Service Principal Names) para ataques Kerberoasting, y relaciones de confianza entre dominios. En entornos mal configurados, es posible realizar consultas anonimas (anonymous bind) que exponen toda esta información sin credenciales.

## Clasificación
- **Fase**: Enumeración
- **MITRE ATT&CK**: T1087.002 (Account Discovery: Domain Account) — usuarios; T1069.002 (Permission Groups Discovery: Domain Groups) — grupos; T1018 (Remote System Discovery) — equipos del dominio
- **Plataforma**: Multi (principalmente Windows/Active Directory)
- **Dificultad**: Intermedia

## Herramientas
- **nmap** (`ldap-rootdse`, `ldap-search`, `ldap-brute`) — enumeración vía NSE
- **ldapsearch** — cliente LDAP nativo para consultas directas al directorio
- **windapsearch** — herramienta Python optimizada para enumeración de Active Directory vía LDAP
- **ldapdomaindump** — volcado completo del dominio en formatos HTML, JSON y grep
- **CrackMapExec/NetExec** — enumeración LDAP integrada con otras técnicas de red

## Comandos / Ejemplos

### Enumeración con Nmap NSE
```bash
# Obtener informacion del Root DSE (naming contexts, dominio, funcionalidad)
nmap -p 389 --script ldap-rootdse <target>
# Resultado: namingContexts, defaultNamingContext, domainFunctionality level

# Busqueda LDAP general (extraer todos los objetos)
nmap -p 389 --script ldap-search --script-args 'ldap.base="dc=domain,dc=com"' <target>

# Fuerza bruta de credenciales LDAP
nmap -p 389 --script ldap-brute \
  --script-args 'userdb=users.txt,passdb=passwords.txt' <target>
```

### Enumeración con ldapsearch
```bash
# Consulta anonima: obtener naming contexts (punto de partida)
ldapsearch -x -H ldap://<target> -b '' -s base '(objectClass=*)' namingContexts

# Consulta anonima: extraer todos los objetos del dominio
ldapsearch -x -H ldap://<target> -b 'dc=domain,dc=com'

# Con credenciales: enumerar todos los usuarios del dominio
ldapsearch -x -H ldap://<target> -D 'CN=usuario,DC=domain,DC=com' -w 'password' \
  -b 'dc=domain,dc=com' '(objectClass=user)' sAMAccountName description memberOf

# Enumerar grupos y sus miembros
ldapsearch -x -H ldap://<target> -D 'user@domain.com' -w 'password' \
  -b 'dc=domain,dc=com' '(objectClass=group)' cn member

# Buscar cuentas con SPN (candidatos a Kerberoasting)
ldapsearch -x -H ldap://<target> -D 'user@domain.com' -w 'password' \
  -b 'dc=domain,dc=com' '(&(objectClass=user)(servicePrincipalName=*))' sAMAccountName servicePrincipalName

# Buscar cuentas deshabilitadas (bit 2 de userAccountControl)
ldapsearch -x -H ldap://<target> -D 'user@domain.com' -w 'password' \
  -b 'dc=domain,dc=com' '(userAccountControl:1.2.840.113556.1.4.803:=2)' sAMAccountName

# Buscar equipos del dominio
ldapsearch -x -H ldap://<target> -D 'user@domain.com' -w 'password' \
  -b 'dc=domain,dc=com' '(objectClass=computer)' cn operatingSystem operatingSystemVersion

# Conexion LDAPS (SSL, puerto 636)
ldapsearch -x -H ldaps://<target>:636 -b 'dc=domain,dc=com'
```

### Enumeración con windapsearch
```bash
# Enumerar usuarios del dominio
python3 windapsearch.py -d domain.com --dc-ip <target> -u 'user@domain.com' -p 'password' --users

# Enumerar grupos
python3 windapsearch.py -d domain.com --dc-ip <target> -u 'user@domain.com' -p 'password' --groups

# Enumerar equipos
python3 windapsearch.py -d domain.com --dc-ip <target> -u 'user@domain.com' -p 'password' --computers

# Enumerar cuentas con privilegios (Domain Admins, etc.)
python3 windapsearch.py -d domain.com --dc-ip <target> -u 'user@domain.com' -p 'password' --privileged-users

# Intentar enumeracion anonima
python3 windapsearch.py -d domain.com --dc-ip <target> --users
```

### Volcado completo con ldapdomaindump
```bash
# Volcar todo el dominio (genera archivos HTML, JSON y grep)
ldapdomaindump -u 'domain\user' -p 'password' ldap://<target>
# Genera: domain_users.html, domain_groups.html, domain_computers.html,
#          domain_policy.html, domain_trusts.html
```

## Contramedidas
- Deshabilitar anonymous bind en el controlador de dominio (configuración por defecto en AD moderno)
- Requerir LDAPS (puerto 636) o LDAP con StartTLS para cifrar las comunicaciones
- Habilitar LDAP Signing para prevenir ataques man-in-the-middle
- Aplicar principio de minimo privilegio: no otorgar permisos de lectura amplia a cuentas de servicio
- Monitorear consultas LDAP anomalas mediante logs de eventos de Windows (Event ID 2889 para binds sin firma)
- Limpiar el campo description de usuarios: no almacenar contraseñas ni información sensible en atributos LDAP

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1087.002: Account Discovery: Domain Account. https://attack.mitre.org/techniques/T1087/002/
- MITRE Corporation. (2024). ATT&CK Technique T1069.002: Permission Groups Discovery: Domain Groups. https://attack.mitre.org/techniques/T1069/002/
