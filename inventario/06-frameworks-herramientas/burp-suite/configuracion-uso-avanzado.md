# Burp Suite: Configuración y Uso Avanzado

## Descripción
Burp Suite es la plataforma líder para realizar auditorías de seguridad en aplicaciones web. Su uso avanzado permite interceptar, analizar y modificar el tráfico HTTP/S entre el navegador y el servidor, automatizar ataques de fuerza bruta o de diccionario con precisión, y gestionar sesiones complejas que requieren tokens dinámicos (CSRF). Es fundamental para identificar vulnerabilidades lógicas, de control de acceso y de inyección que las herramientas automáticas suelen pasar por alto.

## Clasificación
- **Fase**: Análisis de Vulnerabilidades | Explotación
- **MITRE ATT&CK**: T1595.002 (Active Scanning: Vulnerability Scanning); T1190 (Exploit Public-Facing Application)
- **Plataforma**: Web
- **Dificultad**: Intermedia

## Herramientas
- **Proxy** — Intercepta y modifica el tráfico en tiempo real entre el cliente y el servidor.
- **Intruder** — Automatiza ataques personalizados (fuerza bruta, fuzzeo de parámetros, enumeración).
- **Repeater** — Permite reenviar peticiones individuales manualmente para pruebas iterativas.
- **Sequencer** — Analiza la aleatoriedad de los tokens de sesión (cookies, anti-CSRF).
- **BApp Store** — Repositorio de extensiones (ej. Logger++, Autorize, Turbo Intruder) que expanden sus capacidades.

## Comandos / Ejemplos

### Configuración del Alcance (Target Scope)
Definir el scope es crítico para evitar el escaneo accidental de sitios fuera del objetivo y para filtrar el historial de HTTP.
1. Ir a **Target** > **Scope**.
2. Añadir el dominio objetivo (ej. `https://*.ejemplo.com`).
3. En la pestaña **Proxy** > **HTTP history**, marcar la casilla **Show only in-scope items**.

### Ataque Intruder: Pitchfork (Múltiples Payloads)
Útil para ataques que requieren pares de datos relacionados (ej. usuario y contraseña conocidos de una filtración).
```bash
# Paso 1: Seleccionar la petición en el historial y enviarla a Intruder (Ctrl+I).
# Paso 2: En la pestaña Positions, cambiar Attack type a "Pitchfork".
# Paso 3: Definir las posiciones con el símbolo § (ej. user=§admin§&pass=§password§).
# Paso 4: En la pestaña Payloads, asignar una lista distinta a cada posición.
```

### Gestión de Sesiones: Macros para Bypass de CSRF
Cuando un formulario requiere un token anti-CSRF que cambia en cada petición, se debe configurar una macro.
1. **Project options** > **Sessions** > **Session Handling Rules** > **Add**.
2. En **Rule Actions**, añadir **Run a macro**.
3. Seleccionar la petición que obtiene el token (ej. GET /login) y configurar el extractor para capturar el valor del token.
4. Definir el **Scope** de la regla para que solo aplique a las peticiones del Intruder o Repeater que necesitan el token.

### Uso de Grep-Extract en Intruder
Permite extraer datos específicos de las respuestas del servidor para visualizarlos en la tabla de resultados del ataque.
1. En **Intruder** > **Options** > **Grep - Extract**.
2. Hacer clic en **Add**, seleccionar el texto deseado en la respuesta (ej. un mensaje de error o un valor de saldo) y Burp generará el patrón automáticamente.

## Contramedidas
- Implementar HSTS y asegurar que todos los certificados sean válidos para evitar la interceptación sencilla.
- Utilizar tokens anti-CSRF robustos y asegurar que las cookies tengan los flags `HttpOnly` y `Secure`.
- Implementar rate limiting y bloqueos de cuenta para mitigar ataques automatizados mediante Intruder.

## Referencias
- Dafydd, S., & Marcus, P. (2011). *The Web Application Hacker's Handbook: Finding and Exploiting Security Flaws* (2nd ed.). John Wiley & Sons.
- Carlos, P. (2022). *Burp Suite Essentials*. Packt Publishing.
- MITRE Corporation. (2024). ATT&CK Technique T1595.002: Active Scanning. https://attack.mitre.org/techniques/T1595/002/
