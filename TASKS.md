# Plan de Ejecución y Tareas - Inventario de Técnicas

## Roadmap de Implementación

- [x] **Fase 00: Preparación e Infraestructura**
    - [x] Conversión de notas Notion a Markdown (`notas-md/`).
    - [x] Creación de estructura de directorios del inventario (01-08).
    - [x] Definición de agentes y heurísticas en `AGENTS.md`.
- [x] **Fase 01: Reconocimiento** — 14 técnicas (8 pasivo, 6 activo)
- [x] **Fase 02: Enumeración** — 19 técnicas (5 web, 4 red, 6 servicios, 4 fuzzing)
- [ ] **Fase 03: Análisis de Vulnerabilidades**
- [ ] **Fase 04: Explotación**
- [ ] **Fase 05: Post-Explotación**
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
- [ ] Mover versión redundante (18K) de `DOM XSS...` a `redundancia/`.
- [ ] Corregir dobles espacios en nombres de archivos HTML para evitar errores de mapeo futuros.

### Ejecución
- [x] Iniciar piloto: Extraer técnicas de **Reconocimiento Pasivo** (Fase 01/pasivo).
- [ ] Validar que las imágenes en `notas-md/` se referencian correctamente en el nuevo inventario.
- [ ] Continuar con **Fase 03: Análisis de Vulnerabilidades** (scanning/, web/, sistema/).
