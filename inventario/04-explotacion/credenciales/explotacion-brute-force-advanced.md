---
title: Ataques de Fuerza Bruta Avanzados
slug: explotacion-brute-force-advanced
aliases: [Ataques de Fuerza Bruta Avanzados, brute force, password guessing, username enumeration, account enumeration, side-channel auth, response differential, observable response discrepancy, login form fuzzing, credential bruteforce, hydra, medusa, password spraying, timing attack, response timing differential, bcrypt timing oracle, X-Forwarded-For rate-limit bypass, IP-based rate limit bypass]
fase: [Explotación]
plataforma: Multi
dificultad: Intermedia
mitre: [T1110.001, T1110.003]
related: [explotacion-password-spraying]
learning_refs: [portswigger/username-enumeration-via-different-responses, portswigger/username-enumeration-via-subtly-different-responses, portswigger/username-enumeration-via-response-timing]
---

# Ataques de Fuerza Bruta Avanzados

## Descripción
Los ataques de fuerza bruta avanzados van más allá del simple intento de adivinación de contraseñas. Involucran el conocimiento profundo de los flujos de protocolos complejos (como SSH, RDP, MSSQL o formularios web con tokens anti-CSRF) y la gestión de técnicas de evasión para evitar bloqueos de cuenta o detección por IDS/IPS. Esta técnica utiliza diccionarios optimizados, reglas de permutación y ataques de "password spraying" para maximizar la probabilidad de éxito contra servicios corporativos.

## Herramientas
- **Hydra** — herramienta de cracking de login paralela que soporta numerosos protocolos.
- **Medusa** — alternativa rápida a Hydra con un diseño modular para ataques de fuerza bruta.
- **Cupp** — generador de diccionarios personalizados basados en perfiles de usuario (Common User Passwords Profiler).
- **Hashcat** — para ataques offline si se obtienen hashes de contraseñas en lugar de realizar ataques online.

## Comandos / Ejemplos

### Fuerza bruta a SSH con Hydra
```bash
# Ataque paralelo a SSH usando un usuario y una lista de contraseñas
hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 4 ssh://10.10.10.15
# -t 4: limita a 4 hilos para evitar bloqueos por el servicio
```

### Password Spraying contra RDP
```bash
# Probar una única contraseña común contra una lista de usuarios (evita bloqueo de cuenta)
crowbar -b rdp -U users.txt -p 'Winter2023!' -s 192.168.1.0/24
```

### Fuerza bruta a formulario web con token CSRF
```bash
# Hydra puede extraer y enviar tokens dinámicos en cada petición
hydra -l admin -P passwords.txt 10.10.10.10 http-post-form "/login.php:user=^USER^&pass=^PASS^&token=CSRF:F=Login failed"
```

## Contramedidas
- Implementar políticas de contraseñas robustas (longitud mínima, complejidad, rotación).
- Utilizar autenticación de múltiples factores (MFA) en todos los servicios expuestos.
- Configurar bloqueos de cuenta tras un número limitado de intentos fallidos (Account Lockout Policy).
- Implementar CAPTCHA y limitar la tasa de peticiones (Rate Limiting) en interfaces web.

## Referencias
- Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
- MITRE Corporation. (2024). ATT&CK Technique T1110.001: Brute Force: Password Guessing. https://attack.mitre.org/techniques/T1110/001/
