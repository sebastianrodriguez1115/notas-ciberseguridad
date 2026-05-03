# Nombre de la Técnica

## Descripción
Párrafo descriptivo que explica qué es la técnica, en qué contexto se usa, qué permite lograr al atacante, y por qué es relevante en un pentest. Incluir puertos/protocolos si aplica. Redactar en español con ortografía correcta (acentos, eñes, signos de puntuación).

## Clasificación
- **Fase**: Reconocimiento | Enumeración | Análisis de Vulnerabilidades | Explotación | Post-Explotación | Fundamentos | Forense y DFIR
- **MITRE ATT&CK**: T1046 (Network Service Discovery) — usar el ID y nombre completo; incluir sub-técnicas si aplican separadas por punto y coma
- **Plataforma**: Linux | Windows | Web | Red | Multi
- **Dificultad**: Básica | Intermedia | Avanzada

## Herramientas
- **nombre_herramienta** (`módulos`, `scripts`, `flags` relevantes) — descripción breve de qué hace
- **otra_herramienta** — descripción breve

## Comandos / Ejemplos

### Subtítulo descriptivo del bloque
```bash
# Comentario explicando qué hace el comando
comando --flags <target>
# Resultado: descripción breve del output esperado
```

### Otro subtítulo descriptivo
```bash
# Más ejemplos agrupados por herramienta o flujo de trabajo
comando_2 --opciones <target>
```

## Contramedidas
- Contramedida concreta y accionable
- Otra contramedida con contexto de por qué funciona

## Referencias
- Apellido, I. (Año). *Título del libro* (Edición). Editorial.
- Apellido, I. (Año). *Título del libro*. Editorial.
- MITRE Corporation. (2024). ATT&CK Technique TXXXX: Nombre. https://attack.mitre.org/techniques/TXXXX/

<!--
NOTAS PARA EL REDACTOR:

1. CLASIFICACIÓN — Respetar el orden exacto: Fase → MITRE ATT&CK → Plataforma → Dificultad.
   Los dos puntos van FUERA del bold: **Campo**: valor (no **Campo:** valor).

2. HERRAMIENTAS — Cada entrada lleva nombre en bold, módulos/scripts entre paréntesis si
   los tiene, y descripción tras un guión largo (—). No listar solo el nombre.

3. MITRE ATT&CK — Usar el ID más específico posible (sub-técnica > padre).
   Para enumeración de servicios el estándar es T1046 (Network Service Discovery).
   Para vulnerabilidades web: T1190 (Exploit Public-Facing Application).
   Para scanning: T1595.002 (Active Scanning: Vulnerability Scanning).
   Verificar siempre en https://attack.mitre.org/.

   Nota: ATT&CK no tiene mapping limpio para algunas vulnerabilidades de aplicación
   (CSRF, IDOR, race conditions, etc.). En esos casos T1190 es el ID por defecto
   defensible, aunque no sea perfectamente específico. Es una limitación conocida
   de ATT&CK para el dominio de seguridad de aplicaciones, no del inventario.

4. REFERENCIAS — Citar al menos un libro del directorio referencias/ en formato APA 7ma ed.
   Libros disponibles incluyen:
   - Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
   - Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
   - Rahalkar, S. (2017). *Metasploit for Beginners*. Packt Publishing.
   - Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
   - Hertzog, R., & O'Gorman, J. (2017). *Kali Linux Revealed*. Offensive Security.
   - OccupyTheWeb. (2018). *Linux Basics for Hackers*. No Starch Press.
   Para herramientas/repos: Autor. (s.f.). *Nombre* [Software]. GitHub. URL

5. ORTOGRAFÍA — Todo el contenido en español con acentos y ortografía correcta.
   Ver sección "Idioma y Ortografía" en AGENTS.md.

6. DIFICULTAD — Solo usar los tres valores definidos: Básica, Intermedia, Avanzada.
   No usar combinaciones (Básica/Media), ni valores alternativos (Media, Alta, Muy Básica).

7. PLATAFORMA — Solo usar los valores definidos: Linux, Windows, Web, Red, Multi.
   No añadir detalles entre paréntesis. Si aplica a más de una plataforma no-web, usar Multi.
   El detalle "este tool corre en Linux pero su target es Windows" va en la Descripción,
   no en el campo Plataforma. La regla operacional: Plataforma indica el TARGET de la
   técnica, no dónde corre la herramienta.

8. FASE — Por defecto, un solo valor de la lista. Las cinco fases del ciclo clásico de
   pentest son: Reconocimiento | Enumeración | Análisis de Vulnerabilidades | Explotación |
   Post-Explotación. Adicionalmente, las dos categorías de soporte del inventario (07 y 08)
   tienen valores propios:
   - **Fundamentos** — para contenido teórico/fundacional (modelos de red, criptografía
     básica, conceptos generales). Usado por archivos en `07-fundamentos/`.
   - **Forense y DFIR** — para análisis forense, respuesta a incidentes y análisis de
     malware. Usado por archivos en `08-forense-dfir/`.

   Para herramientas o técnicas que genuinamente cruzan fases (BloodHound, enumeración
   Kerberos, Metasploit, Burp Suite, etc.), se permite listar varios valores separados
   por coma+espacio. Ejemplos válidos:
   - **Fase**: Reconocimiento
   - **Fase**: Reconocimiento, Post-Explotación
   - **Fase**: Análisis de Vulnerabilidades, Explotación, Post-Explotación
   - **Fase**: Fundamentos
   - **Fase**: Forense y DFIR

   No usar "/", "|", ni otros separadores. La regla operacional: usar valor compuesto solo
   cuando la técnica realmente se aplica con la misma intención y herramientas en ambas
   fases. Si en una fase se usa con otro propósito, crear archivos separados.

9. SECCIONES OPCIONALES — Las secciones Herramientas, Comandos / Ejemplos y Contramedidas
   son OPCIONALES para contenido conceptual o metodológico que no encaja en el molde de
   "técnica con tools y comandos". Casos típicos:
   - Modelos teóricos (Modelo OSI/TCP-IP, Cyber Kill Chain, MITRE ATT&CK matrix).
   - Ciclos y marcos metodológicos (PICERL, NIST CSF, fases de pentesting).
   - Conceptos fundacionales (criptografía simétrica vs asimétrica, threat modeling).

   Para esos archivos, el cuerpo del documento puede usar secciones propias relevantes
   al tema (ej. "Capas del Modelo OSI", "Fases del Ciclo PICERL", "Componentes del marco").
   Las secciones obligatorias siguen siendo: # Título, ## Descripción, ## Clasificación,
   ## Referencias.

   Para técnicas y herramientas concretas, las 6 secciones (Descripción, Clasificación,
   Herramientas, Comandos / Ejemplos, Contramedidas, Referencias) siguen siendo obligatorias.
-->
