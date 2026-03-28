# Plan de Ejecución y Tareas - Inventario de Técnicas

## Roadmap de Implementación

- [x] **Fase 00: Preparación e Infraestructura**
    - [x] Conversión de notas Notion a Markdown (`notas-md/`).
    - [x] Creación de estructura de directorios del inventario (01-08).
    - [x] Definición de agentes y heurísticas en `AGENTS.md`.
- [x] **Fase 01: Reconocimiento** — 14 técnicas (8 pasivo, 6 activo)
- [x] **Fase 02: Enumeración** — 19 técnicas (5 web, 4 red, 6 servicios, 4 fuzzing)
- [x] **Fase 03: Análisis de Vulnerabilidades** — 20 técnicas (3 scanning, 13 web, 4 sistema)
- [x] **Fase 04: Explotación** — 24 técnicas (7 web, 5 red, 6 sistema, 3 client-side, 3 credenciales)
- [x] **Fase 05: Post-Explotación** — 20 técnicas (7 privesc-linux, 5 privesc-windows, 3 persistencia, 3 lateral-movement, 2 exfiltración)
- [ ] **Fase 06: Frameworks y Herramientas**
- [ ] **Fase 07: Fundamentos**
- [ ] **Fase 08: Forense y DFIR**
- [ ] **Fase 09: Crear un sistema de indices para consultar la informacion facilmente.**

## Workflow Operativo

Para cada sección del inventario, se seguirá este ciclo:

1.  **Planificación**: Definir la subcategoría específica (ej. 01/pasivo).
2.  **Investigación**: El agente `investigador` extrae técnicas de `notas-md/`, `referencias/` e Internet siguiendo las heurísticas de prioridad.
3.  **Redacción**: El agente `redactor` genera los archivos Markdown en la carpeta correspondiente.
4.  **Revisión**: El agente `revisor` valida la precisión técnica y el formato.
5.  **Cierre**: Actualizar `CHANGELOG.md` y marcar como completado en `TASKS.md`.

## Tareas Pendientes Inmediatas (Backlog)

### Limpieza de Fuentes
- [x] Mover versión redundante (18K) de `DOM XSS...` a `redundancia/`.

### Ejecución
- [x] Iniciar piloto: Extraer técnicas de **Reconocimiento Pasivo** (Fase 01/pasivo).
- [x] Enriquecer técnicas críticas (SQLi, XSS, LFI, SSRF) con nuevas referencias especialistas (WAHH).
- [ ] Validar que las imágenes en `notas-md/` se referencian correctamente en el nuevo inventario.
- [x] ~~Continuar con **Fase 03: Análisis de Vulnerabilidades**~~ (scanning/, web/, sistema/) — completada.
- [x] ~~Continuar con **Fase 04: Explotación**~~ (web/, red/, sistema/, client-side/, credenciales/) — completada.
- [x] ~~Continuar con **Fase 05: Post-Explotación**~~ — completada.
- [ ] Continuar con **Fase 06: Frameworks y Herramientas**.
