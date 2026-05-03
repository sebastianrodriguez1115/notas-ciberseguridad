---
title: Crackeo de Hashes (Metodología)
slug: explotacion-hash-cracking
aliases: [Crackeo de Hashes (Metodología), Hash Cracking, hashcat, John the Ripper, JtR, NTLM cracking, TGS cracking, AS-REP cracking]
fase: [Explotación]
plataforma: Multi
dificultad: Intermedia
mitre: [T1110.002]
related: [credential-dumping, pass-the-hash, enumeracion-kerberos, explotacion-mitm-responder]
learning_refs: []
---

# Crackeo de Hashes (Metodología)

## Descripción
Proceso de recuperación de contraseñas en texto plano a partir de sus representaciones hash. Esta técnica se realiza de forma offline una vez que los hashes han sido exfiltrados de una base de datos o de la memoria de un sistema, utilizando potencia de cálculo (CPU/GPU) para comparar millones de combinaciones por segundo.

## Herramientas
- **hashcat** (`-m`, `-a`) — el estándar de la industria para el crackeo de hashes mediante GPU.
- **John the Ripper** — herramienta versátil que soporta una enorme variedad de formatos de hash, ideal para crackeo mediante CPU.
- **CeuL** — para generar diccionarios personalizados basados en el contenido web del objetivo.

## Comandos / Ejemplos

### Crackeo de hashes NTLM (Modo 1000)
```bash
# Ataque de diccionario simple contra hashes NTLM
hashcat -m 1000 ntlm_hashes.txt /usr/share/wordlists/rockyou.txt
```

### Ataque con reglas (Rules)
```bash
# Aplicar reglas de transformación (mayúsculas, números al final, etc.)
hashcat -m 1000 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
```

### Identificación automática de hashes
```bash
# Usar hashid para determinar el tipo de algoritmo
hashid -m '$6$somerandomstring$...'
# Resultado: SHA-512 (Unix) - Hashcat Mode: 1800
```

## Contramedidas
- Utilizar algoritmos de hash "lentos" y resistentes con salting (ej: Argon2, bcrypt, scrypt).
- Implementar políticas de longitud de contraseña robustas (mínimo 14-16 caracteres) para dificultar el crackeo por fuerza bruta.
- Almacenar los hashes de forma segura utilizando Hardware Security Modules (HSM) si es posible.
- Rotar periódicamente las claves secretas utilizadas para el salting (Pepper).

## Referencias
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1110.002: Brute Force: Password Cracking. https://attack.mitre.org/techniques/T1110/002/
