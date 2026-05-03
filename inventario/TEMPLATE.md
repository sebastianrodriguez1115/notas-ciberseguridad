---
title: Nombre de la Técnica
slug: nombre-de-la-tecnica
aliases: [Nombre Alternativo, Acrónimo]
fase: [Reconocimiento]
plataforma: Multi
dificultad: Intermedia
mitre: [T1046]
related: []
learning_refs: []
---

# Nombre de la Técnica

## Descripción
Párrafo descriptivo que explica qué es la técnica, en qué contexto se usa, qué permite lograr al atacante, y por qué es relevante en un pentest. Incluir puertos/protocolos si aplica. Redactar en español con ortografía correcta (acentos, eñes, signos de puntuación).

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

1. FRONTMATTER YAML — Bloque obligatorio al inicio de TODOS los archivos técnicos. Es la
   fuente única de verdad para la metadata. La sección antigua "## Clasificación" en el
   body fue eliminada. Schema:

   - title (string, requerido) — Nombre humano de la técnica. Coincide con el H1.
   - slug (string, requerido, único en todo el inventario) — Identificador estable
     en kebab-case. **Convención: slug = nombre del archivo sin extensión** (ej.
     `analisis-sqli.md` → `analisis-sqli`). El naming de archivos ya impone un
     prefijo de acción (`analisis-`, `explotacion-`, `enumeracion-`, etc.) y un
     acrónimo establecido cuando exista (sqli, xss, csrf, ssrf, idor, lfi-rfi,
     xxe, ssti, jwt, nosqli, adcs); el slug hereda eso. Cuando un archivo se
     renombra (git mv), su slug también cambia. Para búsqueda por tópico cruzando
     fases, usar regex sobre la raíz del tema: `grep -lE "[-_]sqli($|[-.])"` o
     `grep -lE "\bsqli\b"`. Único conflicto operacional: dos archivos con el
     mismo nombre en directorios distintos (ej. fingerprinting-tecnologias-web
     en pasivo y activo). Se resuelve añadiendo modificador al nombre del archivo
     (ej. `fingerprinting-tecnologias-web-activo.md`).
   - aliases (array de strings, requerido, puede ser vacío) — Nombres alternativos
     que un agente/usuario podría buscar. Incluir variantes ES/EN y acrónimos.
     Ejemplo: [Inyección SQL, SQLi, SQL Injection].
   - fase (array de strings, requerido) — SIEMPRE array, aunque sea un único valor.
     Valores permitidos: Reconocimiento | Enumeración | Análisis de Vulnerabilidades |
     Explotación | Post-Explotación | Fundamentos | Forense y DFIR.
   - plataforma (string, requerido) — Un único valor de: Linux | Windows | Web | Red | Multi.
   - dificultad (string, requerido) — Un único valor de: Básica | Intermedia | Avanzada.
   - mitre (array de strings, requerido) — SIEMPRE array. IDs de MITRE ATT&CK con
     sub-técnica si aplica (ej. [T1595.002]). Ver nota MITRE más abajo.
   - related (array de slugs, opcional, default []) — Slugs de otros archivos del
     inventario relacionados. NO usar paths, sólo slugs. El validador resuelve el
     slug a path en Sprint 2. Mantener conservador: sólo cross-references obvios.
   - learning_refs (array de paths, opcional, default []) — Paths relativos a learning/
     que apunten a directorios con writeup.md. Ejemplo:
     [portswigger/visible-error-based-sql-injection]. Ver "Política learning_refs"
     en AGENTS.md.

2. PARES CROSS-FASE — Cuando una técnica tiene archivo de análisis (Fase 03) y de
   explotación (Fase 04) sobre el mismo tópico:
   - Compartir el mismo acrónimo en el nombre de archivo (`analisis-sqli.md` ↔
     `explotacion-sqli.md`). Esto se garantiza por la convención de naming
     documentada en AGENTS.md.
   - Sus slugs heredan los nombres de archivo (`analisis-sqli`, `explotacion-sqli`).
     No hay colisión porque los nombres ya son distintos por el prefijo de acción.
   - Listarse mutuamente en `related:` para que la cross-referencia sea explícita.
   - Para encontrar todos los archivos de un tópico via grep:
     `grep -rlE "[-_]sqli($|[-.])" inventario/` matchea cualquier slug que termine
     con `-sqli` o tenga `sqli` como sub-palabra final (analisis-sqli, explotacion-sqli,
     y futuros como sqli-blind-time si los hubiera).

3. HERRAMIENTAS — Cada entrada lleva nombre en bold, módulos/scripts entre paréntesis si
   los tiene, y descripción tras un guión largo (—). No listar solo el nombre.

4. MITRE ATT&CK — Usar el ID más específico posible (sub-técnica > padre).
   Para enumeración de servicios el estándar es T1046 (Network Service Discovery).
   Para vulnerabilidades web: T1190 (Exploit Public-Facing Application).
   Para scanning: T1595.002 (Active Scanning: Vulnerability Scanning).
   Verificar siempre en https://attack.mitre.org/.

   Nota: ATT&CK no tiene mapping limpio para algunas vulnerabilidades de aplicación
   (CSRF, IDOR, race conditions, etc.). En esos casos T1190 es el ID por defecto
   defensible, aunque no sea perfectamente específico. Es una limitación conocida
   de ATT&CK para el dominio de seguridad de aplicaciones, no del inventario.

5. REFERENCIAS — Citar al menos un libro del directorio referencias/ en formato APA 7ma ed.
   Libros disponibles incluyen:
   - Allen, M. (2022). *Mastering Kali Linux for Advanced Penetration Testing* (4th ed.). Packt Publishing.
   - Harper, A., Linn, R., Sims, S., & Baucom, M. (2018). *Gray Hat Hacking* (5th ed.). McGraw-Hill Education.
   - Rahalkar, S. (2017). *Metasploit for Beginners*. Packt Publishing.
   - Kim, P. (2018). *The Hacker Playbook 3*. Secure Planet, LLC.
   - Hertzog, R., & O'Gorman, J. (2017). *Kali Linux Revealed*. Offensive Security.
   - OccupyTheWeb. (2018). *Linux Basics for Hackers*. No Starch Press.
   Para herramientas/repos: Autor. (s.f.). *Nombre* [Software]. GitHub. URL

6. ORTOGRAFÍA — Todo el contenido en español con acentos y ortografía correcta.
   Ver sección "Idioma y Ortografía" en AGENTS.md.

7. DIFICULTAD — Solo usar los tres valores definidos: Básica, Intermedia, Avanzada.
   No usar combinaciones (Básica/Media), ni valores alternativos (Media, Alta, Muy Básica).

8. PLATAFORMA — Solo usar los valores definidos: Linux, Windows, Web, Red, Multi.
   No añadir detalles entre paréntesis. Si aplica a más de una plataforma no-web, usar Multi.
   El detalle "este tool corre en Linux pero su target es Windows" va en la Descripción,
   no en el campo plataforma. La regla operacional: plataforma indica el TARGET de la
   técnica, no dónde corre la herramienta.

9. FASE — Para herramientas o técnicas que genuinamente cruzan fases (BloodHound,
   enumeración Kerberos, Metasploit, Burp Suite, etc.), listar varios valores en el
   array `fase:`. Ejemplos válidos:
   - fase: [Reconocimiento]
   - fase: [Reconocimiento, Post-Explotación]
   - fase: [Análisis de Vulnerabilidades, Explotación, Post-Explotación]
   - fase: [Fundamentos]
   - fase: [Forense y DFIR]

   La regla operacional: usar valor compuesto solo cuando la técnica realmente se aplica
   con la misma intención y herramientas en ambas fases. Si en una fase se usa con otro
   propósito, crear archivos separados.

10. SECCIONES OPCIONALES — Las secciones Herramientas, Comandos / Ejemplos y Contramedidas
    son OPCIONALES para contenido conceptual o metodológico que no encaja en el molde de
    "técnica con tools y comandos". Casos típicos:
    - Modelos teóricos (Modelo OSI/TCP-IP, Cyber Kill Chain, MITRE ATT&CK matrix).
    - Ciclos y marcos metodológicos (PICERL, NIST CSF, fases de pentesting).
    - Conceptos fundacionales (criptografía simétrica vs asimétrica, threat modeling).

    Para esos archivos, el cuerpo del documento puede usar secciones propias relevantes
    al tema (ej. "Capas del Modelo OSI", "Fases del Ciclo PICERL", "Componentes del marco").
    Las secciones obligatorias siguen siendo: frontmatter YAML completo, # Título,
    ## Descripción, ## Referencias.

    Para técnicas y herramientas concretas, las 5 secciones (Descripción, Herramientas,
    Comandos / Ejemplos, Contramedidas, Referencias) siguen siendo obligatorias.
-->
