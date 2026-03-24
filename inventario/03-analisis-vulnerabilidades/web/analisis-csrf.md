# Análisis de Vulnerabilidades: Cross-Site Request Forgery (CSRF)

## Descripción
El Cross-Site Request Forgery (CSRF) es una vulnerabilidad que obliga a un usuario autenticado a ejecutar acciones no deseadas en una aplicación web en la que se encuentra actualmente autenticado. Un atacante puede engañar al usuario para que haga clic en un enlace o cargue una página maliciosa que realice una solicitud POST (ej. cambiar contraseña, transferir fondos) sin su conocimiento.

## Clasificación
- **Fase**: Análisis de Vulnerabilidades
- **MITRE ATT&CK**: T1185 (Browser Session Hijacking)
- **Plataforma**: Web
- **Dificultad**: Intermedia

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

## Contramedidas
- Implementar tokens Anti-CSRF (Tokens de Sincronización) en cada solicitud que modifique datos.
- Utilizar el atributo `SameSite` (valores `Lax` o `Strict`) en las cookies.
- Implementar la verificación de encabezados `Origin` y `Referer`.
- Requerir re-autenticación para acciones críticas (ej. cambiar contraseña).

## Referencias
- Harper, A., et al. (2018). *Gray Hat Hacking: The Ethical Hacker's Handbook*. McGraw-Hill Education.
- Conklin, W. (2017). *CompTIA Security+ Certification Guide*. McGraw-Hill Education.
