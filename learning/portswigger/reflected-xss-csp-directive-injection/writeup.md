# Writeup: Reflected XSS protected by CSP, with CSP bypass (PortSwigger)

- **Lab**: Reflected XSS protected by CSP, with CSP bypass
- **URL**: https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass
- **Categoría**: XSS / Reflected / CSP bypass / Header injection / Directive precedence
- **Dificultad**: Practitioner

---

## 1. Objetivo

Lograr `alert(1)` en el navegador en una página que tiene un sink XSS reflected pero está "protegida" por una CSP estricta. El truco está en que la CSP misma es injectable.

---

## 2. Reconocimiento

### El sink

El parámetro `?search=` en `/` se refleja **sin sanitizar** dentro del cuerpo HTML, en un `<h1>` de resultados:

```
GET /?search=%3Cimg+src%3D1+onerror%3Dalert%281%29%3E
```

```html
<h1>0 search results for '<img src="1" onerror="alert(1)">'</h1>
```

El `<img>` se renderiza como tag real (no HTML-encoded). Pero el `onerror` no dispara: la CSP corta la ejecución.

### La CSP

Header de la respuesta:

```
Content-Security-Policy: default-src 'self'; object-src 'none';
                         script-src 'self'; style-src 'self';
                         report-uri /csp-report?token=
```

Lo notable:
- `script-src 'self'` sin `'unsafe-inline'` ni `'unsafe-eval'`: bloquea `<script>` inline y handlers `on*=`.
- `report-uri /csp-report?token=` con el valor del query param **vacío**.

Esa última directiva canta. El `token=` apunta a un parámetro de URL controlable. Test:

```
GET /?search=test&token=AAAA
→ Content-Security-Policy: ...; report-uri /csp-report?token=AAAA
```

Reflejo confirmado en el header. **El servidor concatena el valor de `token` al header sin escapar caracteres especiales de CSP.**

---

## 3. Estrategia del bypass

### Inyección de directivas en el header

CSP separa directivas con `;`. Si el `token` contiene `;<directiva>`, el header termina con una directiva extra. Test:

```
GET /?search=test&token=;script-src-elem 'unsafe-inline'
→ Content-Security-Policy: ...; report-uri /csp-report?token=;script-src-elem 'unsafe-inline'
```

El `;` y las comillas simples pasan sin sanitizar. Hay una nueva directiva en el header.

### Por qué `script-src-elem` y no `script-src`

CSP tiene una jerarquía de directivas relacionadas a scripts:

| Directiva | Controla |
|---|---|
| `script-src` | Fallback general para todo lo de scripts |
| `script-src-elem` | Solo `<script>` elements (inline y external) |
| `script-src-attr` | Solo handlers inline (`onclick=`, `onerror=`) |

**Cuando coexisten `script-src` y `script-src-elem` en la misma policy, la más específica gana** para los elementos que cubre. No se intersectan restrictivamente como uno esperaría intuitivamente: si el header dice `script-src 'self'; script-src-elem 'unsafe-inline'`, los `<script>` se rigen SOLO por `script-src-elem`.

Esto sirve porque ya hay `script-src 'self'` plantado por el server. No podemos quitar esa directiva, pero sí podemos añadir una más específica que la sobreescriba para el caso que nos interesa: ejecutar `<script>alert(1)</script>` inline.

---

## 4. Payload final

```
/?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'
```

URL-encoded:

```
/?search=%3Cscript%3Ealert(1)%3C/script%3E&token=;script-src-elem%20%27unsafe-inline%27
```

Pegándolo en la barra del navegador, el browser ejecuta el `<script>` y dispara `alert(1)`. Lab solved.

### Por qué funciona, paso a paso

1. El servidor concatena `token=;script-src-elem 'unsafe-inline'` en el header CSP.
2. El browser parsea el header: ahora hay 6 directivas, no 5. La nueva es `script-src-elem 'unsafe-inline'`.
3. El browser encuentra `<script>alert(1)</script>` inline en el body.
4. Para inline `<script>`, mira `script-src-elem` primero. Encuentra `'unsafe-inline'`. Permitido.
5. Ejecuta. `alert(1)` dispara.

---

## 5. Resumen de la cadena

```mermaid
flowchart TB
    A[1. Sink: ?search= reflejado sin sanitizar en HTML]
    B[2. CSP estricta script-src 'self' bloquea inline]
    C[3. Hallazgo: report-uri /csp-report?token= refleja el token de URL en el header]
    D[4. ; pasa sin sanitizar → inyección de directivas CSP]
    E[5. script-src-elem es más específica que script-src]
    F[6. Inyectar &token=;script-src-elem 'unsafe-inline']
    G[7. <script>alert(1)</script> ahora permitido]
    H[8. alert(1). Lab solved]

    A --> B --> C --> D --> E --> F --> G --> H
```

Cuatro ideas para llevarse:

1. **Si el header CSP contiene un valor que viene de la URL, la CSP es atacable**. La regla "no concatenes input de usuario en headers de seguridad" parece obvia y se viola constantemente, especialmente con `report-uri` que se trata como side-channel administrativo y no como input crítico.
2. **CSP no es monotónica**. Añadir una directiva más específica puede *relajar* la política, no endurecerla. `script-src 'self'; script-src-elem 'unsafe-inline'` es estrictamente menos seguro que solo `script-src 'self'`. Defenders piensan que CSP "sólo agrega restricciones"; atackers explotan la verdad: directivas específicas ganan.
3. **`;` es el separador de directivas dentro del header**. Cualquier reflejo de input en el valor del header CSP que no escape `;` permite añadir directivas. Análogo a SQL injection sobre headers.
4. **`report-uri` es la directiva más a menudo dinámica**, porque típicamente incluye un identificador de tenant, deployment, o session. Eso la convierte en el portador natural del payload de inyección. Vale la pena leer todas las directivas del header CSP en cualquier auditoría buscando interpolaciones.

---

## 6. Contramedidas

Defensas en orden de robustez:

1. **No interpolar input de usuario en headers**, punto. Si el `token` debe pertenecer a la sesión, derivarlo server-side (UUID firmado) y mapearlo internamente, sin exponerlo como query param controlable.
2. **Si no queda otra que reflejar, sanitizar agresivamente**: rechazar (no escapar) cualquier valor de `token` que contenga `;`, `'`, `"`, espacios, o caracteres no `[A-Za-z0-9-_]`. Validar contra una whitelist regex antes de concatenar.
3. **Migrar de `report-uri` a `report-to`** (el reemplazo moderno). `report-to` apunta a un endpoint configurado fuera del header CSP vía `Reporting-Endpoints`, eliminando la necesidad de poner valores dinámicos dentro de la policy.
4. **Headers como bytes opacos en el código**: el código que construye headers de seguridad (CSP, HSTS, Referrer-Policy) debe vivir en una capa con tipos rígidos, no en concatenación de strings ad-hoc. Cualquier valor inyectado debe pasar por un constructor que rechace separadores.
5. **CSP nonce o hash en lugar de allowlist**: incluso si el atacante mete `script-src-elem 'unsafe-inline'`, si el browser ya resolvió el nonce de la directiva original el atacante no puede inyectar nonces nuevos en la página. Más resistente a esta clase de bypass.

### Anti-patrón frecuente

Tratar `report-uri` como "menos crítico" que las demás directivas y permitir personalización via query params. El razonamiento erróneo: "es solo el endpoint de reporte, ¿qué puede salir mal?". Lo que sale mal: cualquier reflejo en el VALOR del header CSP, sin importar cuál directiva lo aloja, abre la puerta a inyección de directivas adicionales.

---

## 7. Referencias

- PortSwigger Web Security Academy. (s.f.). *Lab: Reflected XSS protected by CSP, with CSP bypass*. https://portswigger.net/web-security/cross-site-scripting/content-security-policy/lab-csp-bypass
- PortSwigger Web Security Academy. (s.f.). *Content security policy*. https://portswigger.net/web-security/cross-site-scripting/content-security-policy
- W3C. (2018). *Content Security Policy Level 3*. https://www.w3.org/TR/CSP3/
- MDN Web Docs. (s.f.). *CSP: script-src-elem*. https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src-elem
- MDN Web Docs. (s.f.). *CSP: report-to*. https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to
- Weichselbaum, L., Spagnuolo, M., Lekies, S., & Janc, A. (2016). *CSP Is Dead, Long Live CSP! On the Insecurity of Whitelists and the Future of Content Security Policy*. ACM CCS. https://research.google/pubs/csp-is-dead-long-live-csp-on-the-insecurity-of-whitelists-and-the-future-of-content-security-policy/
- Inventario interno: [`inventario/03-analisis-vulnerabilidades/web/analisis-xss.md`](../../../inventario/03-analisis-vulnerabilidades/web/analisis-xss.md) — caracterización de sinks reflected.
- Inventario interno: [`inventario/04-explotacion/web/explotacion-xss.md`](../../../inventario/04-explotacion/web/explotacion-xss.md) — sección de bypass de CSP.
- Inventario interno: [`inventario/03-analisis-vulnerabilidades/web/analisis-seguridad-cabeceras.md`](../../../inventario/03-analisis-vulnerabilidades/web/analisis-seguridad-cabeceras.md) — auditoría de CSP, incluyendo directivas dinámicas.
- Writeup propio: [`learning/portswigger/reflected-xss-very-strict-csp-dangling-markup/writeup.md`](../reflected-xss-very-strict-csp-dangling-markup/writeup.md) — otro bypass de CSP, allá vía la directiva `form-action` ausente.
- Writeup propio: [`learning/portswigger/reflected-xss-angularjs-sandbox-escape-and-csp/writeup.md`](../reflected-xss-angularjs-sandbox-escape-and-csp/writeup.md) — bypass de CSP vía gadget AngularJS dentro de un host ya whitelisted.
