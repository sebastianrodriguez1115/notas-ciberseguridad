# Banner Grabbing HTTP

## Descripción
Identificación de la versión exacta del servidor web (IIS, Apache, nginx) y el sistema operativo subyacente a partir de banners de servicio HTTP. Los servidores web incluyen información de versión en cabeceras de respuesta como `Server` y `X-Powered-By`. Esta información permite buscar CVEs especificos de esa versión y priorizar vectores de ataque. Es una de las primeras técnicas de enumeración activa en cualquier evaluacion web.

## Clasificación
- **Fase**: Enumeración
- **MITRE ATT&CK**: T1046 (Network Service Discovery)
- **Plataforma**: Web
- **Dificultad**: Básica

## Herramientas
- **nmap** (`-sV -O`) — detección de versión de servicio y sistema operativo
- **netcat** — banner grabbing manual mediante conexión raw TCP
- **curl** — inspeccion de cabeceras HTTP de respuesta

## Comandos / Ejemplos

```bash
# nmap - deteccion de version de servicio y SO
nmap 10.4.18.13 -sV -O

# nmap - escaneo completo con deteccion agresiva
nmap -T4 -p- -A 192.168.20.33
# Flags utiles:
#   -Pn : saltar ping (util si ICMP bloqueado)
#   -sV : deteccion de version de servicio
#   -O  : deteccion de sistema operativo
#   -A  : equivale a -sV -O + traceroute + scripts NSE

# nmap - solo puerto 80 con deteccion de servicio
nmap -sV -p 80,443,8080,8443 TARGET

# netcat - banner grabbing manual (raw TCP)
nc -v 10.4.18.13 80
# Luego escribir: HEAD / HTTP/1.0  [Enter][Enter]
# Resultado: cabeceras HTTP con Server: Apache/2.4.29 (Ubuntu)

# curl - inspeccion de cabeceras sin descargar body
curl -I http://TARGET
curl -I -k https://TARGET   # -k: ignorar SSL invalido

# Ejemplo de resultado de nmap -sV:
# PORT   STATE SERVICE VERSION
# 80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
# |_http-server-header: Apache/2.4.18 (Ubuntu)
```

**Cabeceras clave a analizar:**
```
Server: Apache/2.4.18 (Ubuntu)         → servidor + version + OS
X-Powered-By: PHP/5.6.40               → lenguaje + version
X-AspNet-Version: 4.0.30319            → .NET framework version
X-Generator: WordPress 5.8             → CMS y version
```

**IIS (Windows) vs Apache (Linux):**
- IIS: `Server: Microsoft-IIS/10.0` → indica Windows Server 2016/2019
- Apache: `Server: Apache/2.4.29 (Ubuntu)` → indica distribucion Linux

## Contramedidas
- Configurar el servidor para ocultar la versión exacta:
  - Apache: `ServerTokens Prod` en `httpd.conf`
  - nginx: `server_tokens off` en `nginx.conf`
  - IIS: eliminar cabecera `Server` con `URLScan` o URL Rewrite
- Eliminar la cabecera `X-Powered-By` en PHP: `expose_php = Off` en `php.ini`
- Usar un reverse proxy o WAF que reescriba las cabeceras de respuesta

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1046: Network Service Discovery. https://attack.mitre.org/techniques/T1046/
