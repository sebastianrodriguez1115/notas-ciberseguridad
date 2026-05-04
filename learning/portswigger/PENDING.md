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

(ninguno por ahora — los dos que estaban aquí se completaron usando la ruta same-origin)

## Histórico de razones que pueden volver a aparecer

- **infra-externa-bloqueada-por-firewall**: lab pide exfiltración OOB y no provee exploit server. Resoluble vía Burp Pro o auto-exfiltración same-origin (no vía webhook.site).
- **exploit-server-requerido**: lab depende de inducir a la víctima a visitar URL controlada por el atacante; para eso PortSwigger normalmente provee un "exploit server" gratuito en la barra superior del lab.
