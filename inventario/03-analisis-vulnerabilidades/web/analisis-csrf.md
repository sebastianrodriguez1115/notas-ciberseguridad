---
title: "Análisis de Vulnerabilidades: Cross-Site Request Forgery (CSRF)"
slug: analisis-csrf
aliases: [CSRF, Cross-Site Request Forgery, XSRF, SameSite bypass]
fase: [Análisis de Vulnerabilidades]
plataforma: Web
dificultad: Intermedia
mitre: [T1190]
related: [analisis-xss, analisis-cors, analisis-seguridad-cabeceras]
learning_refs: [portswigger/samesite-lax-bypass-via-cookie-refresh]
---

# Análisis de Vulnerabilidades: Cross-Site Request Forgery (CSRF)

## Descripción
El Cross-Site Request Forgery (CSRF) es una vulnerabilidad que obliga a un usuario autenticado a ejecutar acciones no deseadas en una aplicación web en la que se encuentra actualmente autenticado. Un atacante puede engañar al usuario para que haga clic en un enlace o cargue una página maliciosa que realice una solicitud POST (ej. cambiar contraseña, transferir fondos) sin su conocimiento.

## Herramientas
- **Burp Suite** — Plataforma líder para pruebas de seguridad web, incluyendo generador de pruebas de concepto (PoC) para CSRF.
- **Herramientas de Desarrollador** — Utilidades integradas en el navegador para inspeccionar y manipular solicitudes HTTP.
- **OWASP ZAP** — Escáner de seguridad web de código abierto para identificar vulnerabilidades CSRF.

## Comandos / Ejemplos
Detección manual:
1. Identificar solicitudes que cambien el estado de la aplicación (ej. `POST /update_profile`).
2. Verificar si la solicitud incluye un token de seguridad (`csrf_token`, `nonce`, etc.).
3. Si no hay token, intentar reproducir la solicitud desde una página HTML externa.

Uso del generador de PoC de Burp Suite:
- Click derecho en la solicitud POST relevante -> Engagement tools -> Generate CSRF PoC.
- Guardar el archivo HTML generado y abrirlo en un navegador donde el usuario esté autenticado.

Ejemplo de PoC CSRF manual:
```html
<html>
  <body>
    <form action="http://target.com/api/change_email" method="POST">
      <input type="hidden" name="email" value="attacker@malicious.com" />
      <input type="submit" value="Hacer clic aquí para ganar un premio" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

## Bypasses de SameSite

`SameSite` es una contramedida común pero **no infalible**. Existen escenarios documentados donde un CSRF sigue siendo explotable incluso con `SameSite` activo. Conocerlos es esencial para no dar por seguro un endpoint solo porque las cookies tengan el atributo.

### Bypass 1: Ventana Lax+POST de Chrome (2 minutos)

Chromium implementa una excepción no estándar al modo `Lax`: cuando una cookie **no fija explícitamente** el atributo `SameSite` en su `Set-Cookie` (es decir, Chrome aplica `Lax` por defecto), durante los **primeros ~120 segundos** desde que se emitió la cookie, el navegador **sí la envía en peticiones POST cross-site top-level**. Pasada la ventana, vuelve al comportamiento `Lax` puro.

**Condiciones para que aplique**:
- La cookie de sesión se emite con `Set-Cookie: name=value; ...` **sin** `SameSite=...`.
- La víctima usa Chrome (otros navegadores no implementan esta excepción).
- El POST cross-site se dispara **antes** de los 2 minutos desde el último `Set-Cookie`.

**No aplica si**:
- El servidor escribe `SameSite=Lax` o `SameSite=Strict` explícitamente (la ventana es exclusiva del modo "default").

### Bypass 2: Cookie refresh via OAuth/SSO

Si el sitio renueva su cookie de sesión en un endpoint navegable cross-site (típicamente al final de un flujo OAuth/SSO en `/oauth-callback`, `/social-login` o similar), un atacante puede **forzar la renovación de la cookie de la víctima** desde un sitio externo y luego, dentro de la ventana Lax+POST, enviar la petición CSRF.

Cadena del ataque (combinada con Bypass 1):

1. Sitio atacante abre `window.open('https://victima.com/social-login')`.
2. El navegador de la víctima recorre el flujo OAuth top-level. Si el authorization server tiene una cookie de sesión `SameSite=None` (común en SSO), reconoce a la víctima sin pedir credenciales.
3. El callback emite una `session` nueva en el sitio de la víctima, reiniciando la ventana de 2 min de Lax+POST.
4. `setTimeout` dispara el `POST` CSRF cross-site. Como la cookie tiene segundos de vida, Chrome la adjunta y el ataque pasa.

**Habilitadores típicos**:
- Cookie de sesión sin `SameSite` explícito en el sitio víctima.
- Authorization server externo con `_session=...; SameSite=None`.
- Endpoint navegable que dispara el flujo OAuth completo (`/social-login`).

**Ejemplo práctico documentado**: [`learning/portswigger/samesite-lax-bypass-via-cookie-refresh/writeup.md`](../../../learning/portswigger/samesite-lax-bypass-via-cookie-refresh/writeup.md) — lab de PortSwigger resuelto paso a paso, con captures HTTP reales y exploit final.

### Otros bypasses conocidos (referencia)

- **Lax bypass via method override**: si la app acepta `_method=POST` en query string de un GET, un GET cross-site (que sí lleva la cookie en Lax) puede ejecutar la acción.
- **Strict bypass via client-side redirect**: si una página same-site contiene un redirect controlable por el atacante, puede usarse para que la cookie viaje en el redirect.
- **Strict bypass via sibling domain**: si las cookies se setean en el eTLD+1 (no en el subdominio), un sibling domain comprometido puede leerlas.

## Contramedidas
- Implementar tokens Anti-CSRF (Tokens de Sincronización) en cada solicitud que modifique datos. **Defensa principal — `SameSite` es defensa en profundidad, no sustituto**.
- Utilizar el atributo `SameSite` **explícito** (`Lax` o `Strict`) en las cookies — **nunca dejar que Chrome aplique el default**, porque eso activa la ventana Lax+POST de 2 minutos.
- Implementar la verificación de encabezados `Origin` y `Referer`.
- Requerir re-autenticación para acciones críticas (ej. cambiar contraseña, transferir fondos, cambiar email).
- No emitir cookies de sesión nuevas en endpoints navegables sin gesto explícito del usuario en el sitio (rompe el primitivo del cookie refresh).

## Referencias
- Harper, A., et al. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook*. McGraw-Hill Education.
- Conklin, W. (2017). *CompTIA Security+ Certification Guide*. McGraw-Hill Education.
- PortSwigger Web Security Academy. (s.f.). *Bypassing SameSite cookie restrictions*. https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions
- Chromium Project. (s.f.). *SameSite Updates*. https://www.chromium.org/updates/same-site/
- MDN Web Docs. (s.f.). *Set-Cookie — SameSite attribute*. https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value
- OWASP Foundation. (2021). *Cross-Site Request Forgery Prevention Cheat Sheet*. https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
