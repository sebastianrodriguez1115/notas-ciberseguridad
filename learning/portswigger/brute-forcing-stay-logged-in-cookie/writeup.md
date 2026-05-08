# Writeup: Brute-forcing a stay-logged-in cookie (PortSwigger)

- **Lab**: Brute-forcing a stay-logged-in cookie
- **URL**: https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie
- **Categoría**: Authentication / Other mechanisms — auth cookie con credenciales codificadas
- **Dificultad**: Practitioner
- **Credenciales**: `carlos:12345` (descubiertas vía ataque)

---

## 1. Objetivo

Primer lab del cluster "Other authentication mechanisms" de PortSwigger. Cambia el blanco del ataque: ya no es el form de login con su rate-limit, sino la **cookie persistente** que mantiene la sesión entre cierres de navegador. Esa cookie está mal diseñada de tres formas independientes y cada una basta para romperla. Brute-forcear la cookie de la víctima evita por completo el endpoint `/login`, sus rate-limits, lockouts y todo el resto de la pila defensiva del lab anterior.

### El insight central

La cookie codifica las credenciales de forma reversible-y-verificable:

```
stay-logged-in = base64( username + ":" + md5(password) )
```

El server al recibir la cookie en cada request: la decodifica, separa `user:hash`, busca al usuario, hashea su password almacenado, compara. Si matchea → request autenticado.

Eso convierte el server en un **oracle de hash MD5 sin salt**. El atacante con cualquier wordlist de passwords:
1. Por cada candidato, computa `md5(pwd)`.
2. Arma `cookie = base64("carlos:" + md5_hex)`.
3. Manda `GET /my-account?id=carlos` con esa cookie.
4. Si el body contiene el botón `Update email`, el password es correcto (ese botón sólo aparece autenticado).

100 candidatos sequential = ~30 segundos. Sin lockout ni rate-limit relevantes (la cookie no incrementa el contador del login form).

---

## 2. Reconocimiento

### 2.1 Capturar y entender el formato de la cookie

Login normal con `wiener:peter` marcando "Stay logged in". El server responde con `Set-Cookie: stay-logged-in=d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw; ...`.

```python
>>> base64.b64decode("d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw").decode()
'wiener:51dc30ddc473d43a6011e9ebba6ca770'

>>> hashlib.md5(b"peter").hexdigest()
'51dc30ddc473d43a6011e9ebba6ca770'
```

Confirmado: `cookie = base64(username:md5(password))`. Sin salt, sin HMAC, sin firma del server.

### 2.2 Confirmar el oracle en my-account

Logout del navegador (limpia la sesión normal) pero re-mandar el GET con sólo la cookie `stay-logged-in` válida → response sigue siendo la página autenticada de wiener con el botón `Update email`. La cookie por sí sola es credencial suficiente.

Mandar la misma cookie con un hash modificado (cambiar un byte del hex) → response no contiene `Update email`, el server muestra el form de login. Eso confirma que el server SÍ valida el hash y rechaza cookies mal armadas.

### 2.3 Por qué `Update email` es buen marker

Buscamos un signal binario fácil de detectar y resistente a cambios cosméticos. `Update email` es un texto del button que sólo aparece en el state autenticado de la página. Alternativas peores:
- Status 200 vs 302: ambos pasan en muchos states.
- Length: el server podría inyectar contenido random (CSRF tokens) que varíe entre responses autenticados.
- Presencia del username en el body: depende del lab; en éste se cumple, pero `Update email` es más universal entre apps.

---

## 3. Resolución

Pseudocódigo del ataque:

```python
import base64, hashlib, requests

for pwd in wordlist:
    md5 = hashlib.md5(pwd.encode()).hexdigest()
    cookie = base64.b64encode(f"carlos:{md5}".encode()).decode()
    r = requests.get(f"https://{host}/my-account?id=carlos",
                     cookies={"stay-logged-in": cookie})
    if "Update email" in r.text:
        print(f"found: {pwd}")
        break
```

Output del run real:
```
[*] target=carlos  candidatos=100
[*] formato: base64(carlos:md5(pwd))
[+] cookie: stay-logged-in=Y2FybG9zOjgyN2NjYjBlZWE4YTcwNmM0YzM0YTE2ODkxZjg0ZTdi
[+] status=200 len=3230

[+] credenciales: carlos:12345
```

`12345` es el password #6 del wordlist (después de `123456, password, 12345678, qwerty, 123456789`). Tiempo total: ~2 segundos.

Verificación del lab status: `GET /` → `<section class='academyLabBanner is-solved'>`.

### Comparación con el ataque al login form

| Aspecto | Login form (labs anteriores) | Stay-logged-in cookie (este lab) |
|---|---|---|
| Endpoint | `POST /login` | `GET /my-account?id=carlos` |
| Rate-limit aplicado | Sí (5 fails → lock) | No (cookie no incrementa contador del login) |
| Per-request cost | bcrypt: ~100-200ms | MD5: <1µs |
| Detección de éxito | 302 + `/my-account` Location | `Update email` en body |
| Cuenta lockable | Sí | No |
| Tiempo para 100 candidatos | 1-3 minutos (con/sin batches) | ~2 segundos |

El ataque al cookie sortea **todas** las defensas del login form porque opera contra un endpoint distinto. Lección de auditoría: cuando una app implementa "remember me", auditar ese flujo con la misma seriedad que el login.

---

## 4. Por qué funciona (los tres antipatterns acumulados)

Cualquiera de los tres rompe la cookie por sí solo. Los tres juntos la vuelven trivial.

### 4.1 MD5 es rápido y obsoleto

MD5 no es lento por diseño: ~10⁹ hashes/segundo en una GPU mediana, ~10⁷ en CPU. Una wordlist de 100K passwords se prueba offline en milisegundos. Aún sin GPU, este lab corre en CPU con `hashlib.md5` y completa los 100 candidatos en menos de 1ms de cómputo (el 99% del tiempo es la red).

Para una rainbow table existente — y MD5 sin salt tiene rainbow tables públicas de mil millones de entradas — millones de passwords están pre-resueltos sin computar nada. `crackstation.net` resuelve `5f4dcc3b5aa765d61d8327deb882cf99 → password` en una request.

Hashes que el defender debería usar: bcrypt, Argon2, scrypt. Diseñados para ser **deliberadamente lentos** (cost factor configurable). bcrypt con cost=12 toma ~250ms por hash; brute-forcear 100 candidatos toma 25 segundos sólo en cómputo, sin contar red. Cost factor sube cada año conforme aumenta la potencia del hardware.

### 4.2 Sin salt

El hash MD5 directo de "peter" siempre es `51dc30ddc473d43a6011e9ebba6ca770`. Para todos los usuarios, en cualquier server, hoy y siempre. Eso hace dos cosas malas:

1. **Habilita rainbow tables**: tablas precomputadas de hash→password para los millones de passwords más comunes. El atacante no necesita hashear; sólo busca.
2. **Cross-application leakage**: si otro server filtra hashes MD5 sin salt, esos mismos hashes resuelven contra este server (mismo password = mismo hash).

Salt = un valor random, único por usuario, almacenado junto al hash. `hash = bcrypt(salt + password)`. Mismos passwords producen hashes distintos para usuarios distintos → rainbow tables no aplican, y cracking distribuido tiene que reiniciar por cada usuario.

### 4.3 La cookie es un primitive de "ofrecé el hash y entrá"

Aún si el hash fuera perfecto (Argon2 con salt fuerte), el formato de la cookie sigue siendo malo: el server recibe el hash directamente del cliente y lo compara. Eso significa:

- **Compromiso de la base de datos = compromiso total de las cookies**. Si un atacante obtiene los hashes (SQLi, backup leak, etc.), puede armar cookies válidas para CUALQUIER cuenta sin necesidad de craquear los hashes. Sólo manda `base64(victim:stored_hash)`.
- **Con sesiones opacas, ese mismo compromiso requeriría además forzar nuevas autenticaciones** (que el atacante no puede hacer por la víctima). Las sesiones activas almacenadas en server-side store no son derivables del hash.

El antipattern es **client-side authentication state**. Mejor: cookie = token random opaco (ej. 32 bytes random en hex), que el server resuelve a una sesión en su propio store. La cookie no codifica nada del usuario; es sólo una clave de búsqueda.

### 4.4 Patrón corregido

```python
# MAL — el lab
def set_remember_me_cookie(response, user, password):
    md5 = hashlib.md5(password.encode()).hexdigest()
    cookie_value = base64.b64encode(f"{user.username}:{md5}".encode()).decode()
    response.set_cookie("stay-logged-in", cookie_value)

def authenticate_with_cookie(cookie_value):
    decoded = base64.b64decode(cookie_value).decode()
    username, hash = decoded.split(":")
    user = db.find_user(username)
    if user and hashlib.md5(get_user_password(user).encode()).hexdigest() == hash:
        return user
    return None
```

```python
# BIEN — opaque session token bound a server-side store
import secrets

def set_remember_me_cookie(response, user):
    token = secrets.token_urlsafe(32)  # 32 bytes random, no derivable del usuario
    db.persistent_sessions.insert(
        token=token,
        user_id=user.id,
        expires_at=now() + timedelta(days=30),
        created_ip=request.remote_addr,
    )
    response.set_cookie(
        "stay-logged-in", token,
        secure=True, httponly=True, samesite="Lax",
        max_age=30*86400,
    )

def authenticate_with_cookie(cookie_value):
    session = db.persistent_sessions.find(token=cookie_value)
    if not session or session.expired() or session.revoked:
        return None
    return db.find_user(session.user_id)
```

Diferencias clave:
1. **Token random 32 bytes**: 256 bits de entropía. Brute-force es astronómicamente caro (2²⁵⁵ esperados).
2. **Server-side store**: el server controla qué tokens son válidos. Compromiso de la cookie ≠ compromiso del password. Revocar sesiones específicas es trivial.
3. **Cookie attributes**: `Secure` (HTTPS only), `HttpOnly` (JS no puede leerla), `SameSite=Lax` (mitigación CSRF).
4. **Expiración server-side**: el server decide cuándo invalidar, no el cliente.
5. **Tracking de creación**: IP de origen, user-agent, etc. para detectar uso anómalo del token (alguien lo robó y lo usa desde otra geo).

### 4.5 Variantes peligrosas que NO solucionan el problema

Equivalentemente débiles aún si las "modernizamos":

- `cookie = base64(username + ":" + sha256(password))` — más rápido aún para brute-force que MD5.
- `cookie = base64(username + ":" + bcrypt(password))` — mejor que MD5 pero el cookie sigue siendo cliente-side; compromiso de la DB sigue dando cookies válidas.
- `cookie = aes_encrypt(KEY, username + ":" + password)` — si el atacante extrae KEY del binario o de la memoria, todas las cookies son crackeables. Y el flow sigue siendo "client-side state" en lugar de session lookup.
- `cookie = jwt(payload={username, role}, signed_with_HS256_secret)` — si el secret es brute-forceable (poco entrópico), o si HS256 es vulnerable a key confusion (lab hermano de JWT), mismo problema.

La regla simple: **cualquier cookie cuya validez sea verificable sin consultar un store en el server es brute-forceable o forgeable** dado un input débil. Sólo opaque tokens con server-side lookup son robustos por diseño.

---

## 5. Resumen de la cadena

```mermaid
flowchart TB
    A[1. Login wiener:peter con 'Stay logged in']
    B[2. Capturar cookie stay-logged-in del Set-Cookie response]
    C[3. base64-decode -> wiener:51dc30ddc473d43a6011e9ebba6ca770]
    D[4. md5('peter')==51dc30dd... confirma formato base64 user:md5 pwd]
    E[5. Por cada pwd en candidate-passwords:]
    F[6. cookie = base64 carlos:md5 pwd ]
    G[7. GET /my-account?id=carlos con stay-logged-in=cookie]
    H{8. body contiene 'Update email'?}
    I[9. SI -> credenciales encontradas]
    J[10. NO -> siguiente pwd]

    A --> B --> C --> D --> E --> F --> G --> H
    H -->|si| I
    H -->|no| J --> E
```

Tres ideas para llevarse:

1. **Toda cookie que codifica credenciales de forma verificable client-side es brute-forceable**. La pregunta no es "¿qué cookie usar para remember-me?" sino "¿la cookie es un opaque token o un derivado verificable?". Si la respuesta es "derivado", está rota — al menos tan rota como el hash más débil del derivado.
2. **Hashing de passwords no es lo mismo que hashing genérico**. MD5/SHA-256 son rápidos por diseño (para verificar archivos, firmar mensajes, etc.). Para passwords se necesitan hashes deliberadamente lentos: bcrypt, Argon2, scrypt. El defender que escribe `md5(password)` está cometiendo el error más común y enseñado en la industria.
3. **El "remember me" suele ser el agujero de auditoría más fácil**. Login forms tienen rate-limit, lockouts, captchas, MFA. La cookie persistente típicamente no, porque el defender la considera "menos crítica". Es exactamente al revés: una sesión persistente que pasa por todas las defensas del login form es más crítica que el login form mismo. En auditorías reales, pedirle al cliente "muéstrame el código del flow de remember-me" antes que el del login.

---

## 6. Contramedidas

En orden de robustez:

1. **Reemplazar la cookie derivada por opaque session tokens**. Token random ≥128 bits (typical: 256 bits), almacenado en server-side store con metadata (expiración, IP, user-agent, revocation flag).
2. **Si por arquitectura el cliente DEBE llevar estado**, firmar la cookie con HMAC-SHA256 (o similar) con un secret server-side fuerte. La cookie sigue siendo verificable client-side pero requiere conocer el secret para forjar. Eso es Cookie Signing (firma de integridad), no Cookie Encryption.
3. **Hashing de passwords con algoritmo lento + salt**: bcrypt (cost ≥12), Argon2id (m=64MB, t=3, p=4), o scrypt. Salt random per-user. Rotar el cost factor cada 1-2 años conforme aumenta el hardware.
4. **Atributos seguros en la cookie**: `Secure` (HTTPS only), `HttpOnly` (no accesible vía JS), `SameSite=Lax` o `Strict` (mitigación CSRF). Sin estos, incluso un opaque token bien diseñado se filtra por XSS o CSRF.
5. **Expiración explícita y revocación server-side**: el server puede invalidar cualquier sesión instantáneamente. Logout debe purgar el token del store. Cambio de password debe revocar TODAS las sesiones del usuario.
6. **Detección de anomalías**: usos del mismo token desde IPs/geos drásticamente distintas en corto tiempo, o desde user-agents inconsistentes. Probable indicio de robo de cookie (XSS, MITM, malware en cliente). Forzar re-login.
7. **Limit de sesiones concurrentes per-user** (5-10 dispositivos típico): después se evictan las más antiguas. Reduce blast radius de un token comprometido.
8. **MFA al usar persistent session para acciones sensibles** (cambiar password, ver datos privados, transacciones financieras). El "remember me" autentica para acciones rutinarias; las críticas requieren factor adicional aunque la sesión esté activa.

---

## 7. Referencias

- PortSwigger Web Security Academy. (s.f.). *Lab: Brute-forcing a stay-logged-in cookie*. https://portswigger.net/web-security/authentication/other-mechanisms/lab-brute-forcing-a-stay-logged-in-cookie
- PortSwigger Web Security Academy. (s.f.). *Other authentication mechanisms*. https://portswigger.net/web-security/authentication/other-mechanisms
- OWASP Foundation. (s.f.). *Session Management Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP Foundation. (s.f.). *Password Storage Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html — guía sobre bcrypt/Argon2/scrypt y por qué MD5/SHA-256 son inadecuados para passwords.
- OWASP Foundation. (s.f.). *Authentication Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html — sección "Remember-Me Function".
- MITRE Corporation. (2024). *CWE-836: Use of Password Hash Instead of Password for Authentication*. https://cwe.mitre.org/data/definitions/836.html — CWE específico de este patrón.
- MITRE Corporation. (2024). *CWE-916: Use of Password Hash With Insufficient Computational Effort*. https://cwe.mitre.org/data/definitions/916.html — MD5/SHA sin coste para passwords.
- MITRE Corporation. (2024). *CWE-759: Use of a One-Way Hash without a Salt*. https://cwe.mitre.org/data/definitions/759.html
- MITRE Corporation. (2024). *ATT&CK Technique T1539: Steal Web Session Cookie*. https://attack.mitre.org/techniques/T1539/
- Provos, N., & Mazières, D. (1999). *A Future-Adaptable Password Scheme*. USENIX. https://www.usenix.org/legacy/event/usenix99/provos/provos_html/ — paper original de bcrypt.
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook* (2nd ed.). Wiley. Cap. 7 (Attacking Session Management).
- Hoffman, A. (2020). *Web Application Security*. O'Reilly Media. Cap. 9-10.
- Writeups hermanos:
  - [`learning/portswigger/username-enumeration-via-account-lock/writeup.md`](../username-enumeration-via-account-lock/writeup.md) — el lab anterior tackled el login form; este sortea ese path.
  - Serie de auth completa en `learning_refs:` de [`inventario/04-explotacion/web/explotacion-session-cookies-debiles.md`](../../../inventario/04-explotacion/web/explotacion-session-cookies-debiles.md).
- Inventario interno: [`inventario/04-explotacion/web/explotacion-session-cookies-debiles.md`](../../../inventario/04-explotacion/web/explotacion-session-cookies-debiles.md) (nuevo archivo creado para este cluster).
- Script: [`cookie_brute.py`](cookie_brute.py).
