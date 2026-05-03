# CHANGELOG - Inventario de Técnicas de Ciberseguridad

Todos los cambios notables en este proyecto serán documentados en este archivo.

## [2026-05-03] — Sesión 19k (Review crítico ronda 5)

Dos hallazgos (Media + Media). El primero es un bug puntual; el segundo me hizo replantear el approach de la ronda 4.

### Hallazgo 1 (Media) — slug emitido sin pasar por yaml_scalar
- `build_frontmatter()` quotaba `title` y los arrays vía `yaml_scalar`/`yaml_array`, pero emitía `slug`, `plataforma`, `dificultad` con f-string raw. Un legacy `no.md` migraba a `slug: no` que PyYAML resuelve a `False`. Después validate.py reporta `slug must be string, got bool` y se rompe la convención `slug == path.stem`.
- **Fix**: los 3 campos pasan por `yaml_scalar` ahora. Los enums actuales (Web/Linux/Avanzada/etc.) no colisionan con scalars reservados, pero la emisión defensiva resiste cambios futuros del schema.
- **Tests**: `test_build_frontmatter_slug_round_trip` con 6 slugs problemáticos (no/yes/true/null/123/0xff). `test_build_frontmatter_plataforma_dificultad_through_yaml_scalar` con valores hipotéticos `On`/`1.0`.

### Hallazgo 2 (Media) — Cobertura incompleta de tipos implícitos PyYAML
- La ronda 4 había añadido regex para bool/null/números, pero PyYAML también resuelve **timestamps** (`2024-01-01` → `datetime.date`) y **special floats** (`.nan`, `.inf`, `+.inf`, `-.inf` → `float`). Mis regex no los cubrían.
- **Decisión arquitectónica**: en lugar de seguir enumerando categorías YAML 1.1 una por una (ya van 4 sesiones encontrando casos faltantes), delegar a PyYAML mismo via round-trip. Si `yaml.safe_load(f"_: {s}\\n")` no devuelve `{_: <s>}` con `<s>` como string igual al original, hay que quotar. Cubre TODA resolución implícita sin enumerarla.
- **Implementación**: `_needs_quoting()` reescrito. Mantiene early-exit rápido para chars especiales, prefijos reservados, trailing whitespace, y string vacío. Para todo lo demás, llama a `yaml.safe_load` y verifica round-trip.
- **Performance**: ~1ms por scalar via PyYAML. Para migrar 124 archivos (~10 scalars c/u = 1240 calls) → < 2s total. Aceptable.
- **Bonus**: la delegación me corrigió mi propia enumeración previa. Tests de ronda 4 asumían que `Y`, `n`, `None`, `1e10`, `0o777` se resolvían pero PyYAML los lee como string. Eran sobre-aserciones. La nueva implementación correctamente los marca como safe-unquoted.

### Tests reorganizados
- `test_yaml_scalar_quotes_pyyaml_implicit_types`: parametrize unificado con todos los casos que PyYAML SÍ resuelve. Listas internas categorizadas: `_RESOLVES_TO_BOOL`, `_RESOLVES_TO_NULL`, `_RESOLVES_TO_NUMBER`, `_RESOLVES_TO_DATE`, `_RESOLVES_TO_DATETIME`, `_RESOLVES_TO_SPECIAL_FLOAT`. Verificadas empíricamente con `yaml.safe_load` antes de añadir.
- `test_yaml_scalar_does_not_quote_safe_strings`: parametrize con casos que PyYAML lee como string. Documenta explícitamente qué NO se quota (Y, n, None, 1e10, 0o777, etc.) para no regresionar a sobre-quoting.
- `test_build_frontmatter_round_trip` ampliado con `2024-01-01`, `.nan`, `+.inf` además de los previos.
- `test_build_frontmatter_slug_round_trip` y `test_build_frontmatter_plataforma_dificultad_through_yaml_scalar` nuevos.

### Sutileza encontrada por los tests
PyYAML requiere **signo explícito en el exponente** para resolver float: `1.0e+10` → float, `1.0e10` → string. Mismo con `1.0E5` → string (no exp). Documentado en el comentario del regex `_RESOLVES_TO_NUMBER`.

### Estado tras ronda 5
- `bash scripts/check.sh` → all green.
- 143 tests passing (40 nuevos respecto a sesión 19j).
- 124/124 validate OK.
- `build_indexes --check` up to date.

## [2026-05-03] — Sesión 19j (Review crítico ronda 4: YAML implicit type resolution)

Un hallazgo (Media) en `migrate_frontmatter.py` sobre resolución implícita de tipos YAML 1.1. Bug profundo y futuro-proof. Aplicado con cobertura paramétrica.

### Hallazgo (Media)
PyYAML safe_load resuelve scalars no-quoted como `No`, `Yes`, `True`, `Off`, `null`, `~` a bool/null por la spec YAML 1.1. Lo mismo con strings que parecen números (`123`, `1.5`, `0xFF`, `1e10`). El emitter manual de migrate_frontmatter sólo chequeaba caracteres especiales (`:`, `,`, `[`, etc.) e ignoraba estas categorías reservadas. Reproduce: un legacy `# No` migra a:

```yaml
title: No
slug: no
aliases: [No]
```

Que PyYAML parsea como `{title: False, slug: False, aliases: [False]}`. Después validate.py reporta `title must be string, got bool`. El frontmatter es objetivamente inválido.

### Decisión: ampliar quoting manual en lugar de yaml.safe_dump
Evalué la sugerencia del reviewer de usar `yaml.safe_dump`. Rechazado: el default rompe la convención inline para arrays (`fase:\n- Reconocimiento` en lugar de `fase: [Reconocimiento]`). Forzar `default_flow_style=True` global produce mappings en flow `{title: ..., slug: ..., ...}` que es peor. No vale el rework de los 124 archivos por un fix que se puede hacer en 30 líneas con regex bien diseñadas.

### Fix
- Nuevo `_needs_quoting()` consulta tres regex: `_YAML_RESERVED_SCALARS` (true/false/yes/no/on/off/y/n/null/None/~ case-insensitive), `_YAML_NUMBER` (int/float/exp), `_YAML_NUMBER_RADIX` (0x/0o/0b/octal). También cubre flow-context special chars, prefijos reservados y trailing whitespace.
- `yaml_scalar()` reescrito para usar `_needs_quoting()` y escapar `\` y `"` cuando quota.
- `yaml_array()` ahora delega cada item a `yaml_scalar()` para uniformar la lógica.

### Tests nuevos (37 casos via parametrize)
- `test_yaml_scalar_quotes_reserved_yaml_scalars` (16 casos paramétricos): No/no/NO, Yes/yes, true/True/TRUE, false, On/off, Y/n, null, None, ~. Cada uno verifica que el output empieza con `"`.
- `test_yaml_scalar_quotes_numbers` (9 casos): 123, 0, -7, 1.5, .5, 1e10, 0xFF, 0o777, 0b101.
- `test_yaml_scalar_plain_strings_unquoted`: "plain", "Hello World", "Foo (Bar)" no requieren quote.
- `test_yaml_scalar_empty_string_is_quoted`: `""` quotado para evitar resolución implícita a null.
- `test_yaml_scalar_rejects_non_string`: TypeError si recibe int.
- `test_build_frontmatter_round_trip` (9 casos paramétricos): emite frontmatter con title `No`, `Yes`, `True`, `null`, `123`, `1.5`, `Foo: "Bar"`, plain, complejo, parsea con yaml.safe_load, asserts que `title == original`. Esto cubre el escenario completo end-to-end.

### Estado tras ronda 4
- `bash scripts/check.sh` → all green.
- 103 tests passing (37 nuevos respecto a sesión 19i, mayormente paramétricos).
- 124/124 validate OK (no afecta data ya migrada porque ningún title existente caía en los casos reservados).
- `build_indexes --check` up to date.

## [2026-05-03] — Sesión 19i (Review crítico ronda 3)

Cuatro hallazgos del review ronda 3 sobre la sesión 19h. Los cuatro válidos. Aplicados con tests nuevos para cada bug de código.

### Hallazgo 1 (Media) — yaml_array generaba YAML inválido con comillas internas
- `migrate_frontmatter.py:yaml_array()` quotaba valores con caracteres YAML especiales pero NO escapaba comillas internas. Un title legacy `Foo: "Bar"` derivado a `aliases: ["Foo: "Bar""]` produce un YAML que PyYAML no parsea (token mismatch: el cierre `"` se interpreta antes de tiempo).
- **Fix**: `yaml_array()` ahora hace `v.replace('"', '\\"')` antes de quotar, consistente con `yaml_scalar()` que ya lo hacía. 2 tests nuevos: `test_yaml_array_escapes_internal_quotes` (verifica el escape literal y que PyYAML pueda parsear el output) y `test_yaml_array_with_aliases_derived_from_titled_quote` (caso end-to-end via build_frontmatter).
- En el inventario actual no había títulos con `"` interno, así que no afectaba data ya migrada. Es protección para futuras migraciones.

### Hallazgo 2 (Baja) — cross_validate iteraba string carácter por carácter
- Si el YAML traía `related: foo` (string) en lugar de `related: [foo]`, `validate_file` reportaba correctamente `related must be array`, pero `cross_validate` hacía `for slug in fm.get("related") or []:` lo cual itera la string como secuencia de caracteres `'f', 'o', 'o'` y reportaba 3 errores falsos. No rompía el exit code (ya había errors de tipo) pero ensuciaba el diagnóstico.
- **Fix**: `cross_validate` ahora hace `if not isinstance(related_val, list): related_val = []` antes de iterar. Mismo guard para `learning_refs`. 2 tests nuevos: `test_cross_validate_skips_non_list_related` y `test_cross_validate_skips_non_list_learning_refs`.

### Hallazgo 3 (Baja) — AGENTS.md mentía sobre git mv
- La sección "Slug = nombre de archivo" decía: "se preserva si renombras vía `git mv`". Eso contradice el validador, que exige `slug == path.stem`. Tras un `git mv`, el filename cambia pero el `slug:` dentro del frontmatter NO se auto-actualiza, así que el archivo queda en estado inválido hasta que se edite a mano.
- **Fix**: AGENTS.md aclara que después de `git mv` hay que actualizar el `slug:` a mano para que coincida con el nuevo filename, y describe el workflow `git mv old.md new.md && sed -i 's/^slug: old$/slug: new/' new.md && bash scripts/check.sh`. El validador detecta el drift con el mensaje `slug must equal filename without extension`.

### Hallazgo 4 (Baja) — CHANGELOG miscount
- Sesión 19h decía "62 tests passing (4 nuevos: slug validation x3, cross_validate x1)" pero la suite pasó de 57 a 62, son 5 tests nuevos: 4 de slug + 1 de cross_validate.
- **Fix**: corregido a "5 nuevos: slug validation x4, cross_validate failure x1".

### Estado tras ronda 3
- `bash scripts/check.sh` → all green.
- 66 tests passing (4 nuevos respecto a sesión 19h: 2 yaml_array + 2 cross_validate skip).
- 124/124 validate OK.
- `build_indexes --check` up to date.

## [2026-05-03] — Sesión 19h (Review crítico ronda 2)

Cuatro hallazgos del review ronda 2 sobre la sesión 19g. Los cuatro válidos. Aplicados con tests adicionales y un script de ritual para evitar el proceso fallado que disparó el primer hallazgo.

### Hallazgo 1 (Alta) — `build_indexes --check` estaba stale
- `inventario/meta/by-mitre.md` todavía listaba `fingerprinting-tecnologias-web-activo` bajo `T1592` aunque la data ya había sido fixeada a `mitre: [T1592.002]` en la sesión 19g.
- Causa raíz (proceso): tras fixear la data, no se re-corrió `build_indexes`. El CHANGELOG decía "up to date" pero no lo estaba.
- **Fix data**: regenerado `inventario/meta/by-mitre.md`.
- **Fix proceso**: nuevo script `scripts/check.sh` ejecuta `pytest + validate + build_indexes --check` en orden, falla en el primero. AGENTS.md workflow añade un nuevo "Paso 5 — Verificación pre-commit" que invoca este ritual; el actual paso 5 (CHANGELOG) pasa a ser paso 6.

### Hallazgo 2 (Media) — validate.py no enforzaba slug == filename
- La nueva convención "slug = filename sin extensión" estaba documentada en TEMPLATE.md y AGENTS.md, pero el validador sólo verificaba tipo y unicidad. Un archivo `analisis-sqli.md` con `slug: sqli` pasaría aunque contradice la convención.
- **Fix**: validator ahora exige `slug == path.stem` Y formato kebab-case via regex `^[a-z0-9]+(-[a-z0-9]+)*$`. 4 tests nuevos (`test_slug_must_equal_filename`, `test_slug_kebab_case_rejected_uppercase`, `test_slug_kebab_case_rejected_underscore`, `test_slug_kebab_case_passes_simple`).
- **Verificación**: 124/124 archivos siguen pasando (todos ya cumplen la convención porque la migración derivó slug de filename desde el inicio).

### Hallazgo 3 (Media) — cross_validate exception silenciaba errores globales
- El try/except defensivo capturaba el crash de `cross_validate`, imprimía "FATAL" pero el script seguía corriendo y exit code podía quedar 0 si no había errores per-file. CI no lo notaría.
- **Fix**: nueva flag `cross_failed` se setea en el except; si está, se imprime mensaje "marcando como failure" y sale con código 1. Test nuevo `test_main_exits_nonzero_when_cross_validate_crashes` inyecta un `cross_validate` roto y verifica `SystemExit.code == 1`.

### Hallazgo 4 (Baja) — Doc drift sobre learning_refs
- Docstring de `validate.py` decía "writeup.md o algún .md", AGENTS.md decía "o equivalente Markdown estructurado", aunque el código (post-ronda 1) ya exigía `writeup.md` exacto.
- **Fix**: docstring de `validate.py` actualizado a "estricto, ver Política learning_refs en AGENTS.md". AGENTS.md sección "Política learning_refs" reescrita: exige nombre exacto `writeup.md`, menciona explícitamente que material multi-capítulo (ej. tryhackme/abusingwindowsinternals/) debe consolidarse en un `writeup.md` que orqueste/linkee los chapters, y que el validador rechaza directorios sin él.

### Estado tras ronda 2
- `bash scripts/check.sh` → all green.
- 62 tests passing (5 nuevos respecto a sesión 19g: slug validation x4, cross_validate failure x1).
- 124/124 validate OK.
- `build_indexes --check` up to date.

## [2026-05-03] — Sesión 19g (Tests + bug encontrado por test)

Tras aplicar los fixes del review crítico, se construyó una suite de tests con pytest para los 3 scripts de tooling. Cubre: type-check defensivo, casos felices, regresiones específicas del review (plataforma como lista, title como int, related con int, learning_refs sin writeup.md, --check no toca filesystem).

### Suite de tests (`scripts/tests/`)
- `conftest.py`: fixtures `sandbox` (tmp_path con inventario/ y learning/) y `write_md` (helper que genera `.md` con frontmatter formateado correctamente). Añade `scripts/` al sys.path para imports.
- `test_validate.py` (23 tests): happy path, missing fields, enum invalidos, type checks defensivos, slug duplicado, title↔H1, MITRE format, mitre vacío sólo para conceptual, related dangling, learning_refs con/sin writeup.md, sección Clasificación residual.
- `test_migrate_frontmatter.py` (18 tests): yaml_scalar/yaml_array, extract_h1, extract_clasificacion (simple, compound fase, multilínea MITRE, MITRE en link markdown), happy path, skip si ya tiene frontmatter, dry-run no escribe, title con `:` quotado, mitre vacío sólo para conceptual, validación de enums.
- `test_build_indexes.py` (16 tests): short_title, render_table, collect_files exclusiones, regen_leaf_index (basic, idempotent, preserva narrativa, backlinks 1 y 2 niveles, sort por display title), build_topics, build_facet, --check no crea meta/, --check no modifica archivos, full run escribe.

### Bug encontrado por los tests
El test `test_extract_clasificacion_linked_mitre` falló al primer intento. Causa: `migrate_frontmatter.py` extraía T-IDs de cualquier parte del bloque MITRE incluyendo URLs de markdown links. Para `[T1592.002](https://attack.mitre.org/techniques/T1592/002/)` capturaba `T1592.002` (legítimo) y `T1592` (extraído del path del URL).

- Confirmado en datos reales: `inventario/02-enumeracion/web/fingerprinting-tecnologias-web-activo.md` tenía `mitre: [T1592.002, T1592]`.
- **Fix script**: pre-procesar el bloque MITRE reemplazando `[texto](url)` por `texto` antes de extraer T-IDs. Así URLs no contaminan la extracción.
- **Fix data**: corregido el archivo afectado a `mitre: [T1592.002]`.
- Otros archivos con T1XXX y T1XXX.NNN ambos (kerberos, bloodhound, pivoting-tunneling, process-injection) son intencionales: tienen multi-línea explícita con técnica padre + sub-técnicas distintas. No son afectados.

### Otros fixes menores
- `.gitignore` añade `__pycache__/`, `*.pyc`, `.pytest_cache/`. El commit anterior había incluido sin querer un `.pyc` que se untrackea aquí.

### Estado tras tests
- `python3 -m pytest scripts/tests/` → 57 passed in 0.12s.
- `python3 scripts/validate.py` → 124/124 OK.
- `python3 scripts/build_indexes.py --check` → up to date.

## [2026-05-03] — Sesión 19f (Fixes del review crítico de Sprint 2)

Pasada de fixes derivada de un review crítico externo del trabajo de Sprint 2. Cuatro hallazgos auditados, los cuatro corregidos. Discusión arquitectónica resuelta sobre la convención de slugs.

### Hallazgo 1 (Alta): doc drift en convención de slug
- TEMPLATE.md y AGENTS.md declaraban "análisis usa slug base (`sqli`), explotación usa `<slug>-explotacion` (`sqli-explotacion`)" pero la realidad implementada era `slug = filename sin extensión` (`analisis-sqli`, `explotacion-sqli`).
- **Decisión arquitectónica**: alinear docs a la implementación, no al revés. Razones: slug=filename es derivable mecánicamente, invariante con `git mv`, y la "regla base+suffix" generaba ambigüedad para pares no-clásicos (pasivo/activo no tiene "base" obvio). Búsqueda por tópico cruzando fases vía `find inventario -name "*-sqli.md"` o `grep -rlE "^slug: .*[-_]sqli($|[-.])"`. Trade-off aceptado: un grep ligeramente más complejo a cambio de cero ambigüedad mental.
- **Cambios**: TEMPLATE.md notas 1 y 2 reescritas. AGENTS.md sección "Pares cross-fase" y cookbook actualizados para reflejar la convención real.

### Hallazgo 2 (Media): validate.py crasheaba con YAML mal tipado
- `plataforma: [Web]` (lista en lugar de string) provocaba `TypeError: unhashable type: 'list'` al evaluar `plat not in PLATAFORMA_VALID`. Title no-string fallaba en `.strip()`. Un solo archivo malformado abortaba todo el run.
- **Fix**: type checks defensivos por campo. Cada error se reporta como `plataforma must be string, got list` y el run continúa con los siguientes archivos. Red de seguridad adicional: `try/except` en el loop principal de `main()` captura cualquier edge case que escape los type checks y lo reporta sin abortar.
- **Verificación**: tests sintéticos con `plataforma: [Web]`, `title: 42`, `related: [123, "valid"]` producen mensajes de error claros, todos los archivos siguen procesándose.

### Hallazgo 3 (Media): tipos internos de related/learning_refs + writeup.md strict
- `related: [123, "foo"]` rompía `slug not in all_slugs` con TypeError. `learning_refs: [123]` rompía `LEARNING / 123`.
- **Fix 3a**: type-check de items dentro de los arrays. Items no-string se reportan como error y se saltan en cross-validation (en lugar de crashear).
- **Fix 3b**: la política en AGENTS.md exigía writeup.md o equivalente Markdown estructurado, pero el validador aceptaba cualquier `*.md`. Ahora exige `writeup.md` específicamente. Razón: las directorios de course material multi-capítulo (como `tryhackme/abusingwindowsinternals/`) ya tienen writeup.md consolidado; esta política fuerza a futuros writeups a hacer lo mismo en lugar de aceptar fragmentos sueltos.
- **Verificación**: las 4 archivos del inventario con learning_refs apuntan a dirs con writeup.md y siguen pasando. Test sintético con dir conteniendo sólo `notes.md` produce error: `learning_refs path missing writeup.md`.

### Hallazgo 4 (Baja): build_indexes.py --check tocaba filesystem
- `META_DIR.mkdir(exist_ok=True)` se ejecutaba incondicionalmente, creando `inventario/meta/` aunque el modo `--check` declarara no modificar nada.
- **Fix**: mover `META_DIR.mkdir` dentro de la rama `if not args.check`. CI puede ahora correr `build_indexes.py --check` sobre un repo limpio sin ensuciar el árbol.

### Estado tras fixes
- `python3 scripts/validate.py` → 124/124 OK.
- `python3 scripts/build_indexes.py --check` → up to date, no filesystem changes.
- 0 archivos del inventario afectados (los fixes son sólo en docs y scripts).
- Tests defensivos pasan: validador no crashea con YAML mal tipado.

## [2026-05-03] — Sesión 19e (Enriquecimiento de aliases + related + learning_refs)

Pasada de enriquecimiento sobre 39 topics frecuentes para que las búsquedas por sinónimo y la cross-referencia entre fases funcionen. Aplicado vía script one-shot inline.

### Topics enriquecidos (39 archivos)
- **Web**: analisis-sqli ↔ explotacion-sqli, analisis-xss, analisis-csrf, analisis-cors, analisis-idor, analisis-ssrf, analisis-xxe, analisis-ssti, analisis-lfi-rfi, analisis-deserialization ↔ explotacion-deserialization, explotacion-nosqli, explotacion-jwt, explotacion-auth-bypass-oauth, explotacion-fileupload.
- **Red/AD**: enumeracion-kerberos (Kerberoasting, AS-REP Roasting, GetUserSPNs, GetNPUsers), enumeracion-ldap, enumeracion-smb (enum4linux, smbclient, CIFS), enumeracion-nfs, enumeracion-snmp, enumeracion-dns.
- **Fuzzing**: fuzzing-directorios-archivos (gobuster, ffuf, dirsearch), fuzzing-subdominios-vhosts, fuzzing-parametros (Arjun, ParamMiner), fuzzing-lfi-ssrf.
- **Post-Explotación**: pass-the-hash (PtH), credential-dumping (mimikatz, LSASS dump, DCSync, DPAPI), bloodhound (SharpHound, AD attack paths), ejecucion-remota-windows (psexec, wmiexec, atexec).
- **DBs**: enumeracion-mssql (xp_cmdshell), enumeracion-mysql (MariaDB), enumeracion-mongodb.
- **Frameworks**: metasploit-avanzado (msfconsole, msfvenom), configuracion-uso-avanzado (Burp Proxy/Repeater/Intruder), empire-framework (Starkiller).
- **Sistema**: explotacion-eternalblue (MS17-010), explotacion-zerologon (CVE-2020-1472), explotacion-shellshock.

### Cross-references añadidas
- `related:` en cada par cross-fase listado mutuamente (analisis-sqli ↔ explotacion-sqli, etc.).
- `related:` cross-categoría en topics que cruzan disciplinas (kerberos ↔ ldap ↔ smb ↔ bloodhound; jwt ↔ oauth-bypass; fuzzing ↔ topics web).

### `learning_refs:` añadidos
- 6 archivos del inventario referencian writeups de `learning/portswigger/`:
  - **SQLi (analisis + explotacion)**: 5 labs (visible-error-based, blind-time-delays, blind-time-delays-info-retrieval, blind-out-of-band, sqli-filter-bypass-xml-encoding).
  - **XSS (analisis)**: 4 labs (reflected-xss-canonical-link-tag, reflected-xss-js-string-angle-quotes-encoded, reflected-xss-js-string-sq-backslash-escaped, stored-xss-onclick-html-entity-bypass).
  - **CSRF (analisis)**: 1 lab (samesite-lax-bypass-via-cookie-refresh).

### Fix derivado
- `scripts/validate.py` ahora excluye `inventario/meta/` y `inventario/TOPICS.md` (auto-generados sin frontmatter).

### Estado tras enriquecimiento
- `python3 scripts/validate.py` → 124/124 OK con cross-references resueltas.
- `python3 scripts/build_indexes.py --check` → up to date (TOPICS.md regenerado para reflejar nuevas aliases/related/learning_refs).
- Discoverabilidad por sinónimo funciona: `grep -lE "^aliases:.*Kerberoasting"` encuentra `enumeracion-kerberos.md`, `grep -lE "^aliases:.*\bPtH\b"` encuentra `pass-the-hash.md`, etc.
- Pares cross-fase siempre se encuentran mutuamente vía `related:` (ej. desde explotacion-sqli puedes saltar a analisis-sqli y a los 5 writeups PortSwigger).

## [2026-05-03] — Sesión 19d (Sprint 2: validate.py + build_indexes.py)

Sprint 2 del plan de discoverabilidad. Tooling para validar la integridad del frontmatter y regenerar índices automáticamente.

### `scripts/validate.py` (nuevo)
- Valida los 124 archivos técnicos del inventario contra el schema documentado en TEMPLATE.md y AGENTS.md.
- Comprueba: presencia de frontmatter, parseable como YAML, campos requeridos (title, slug, aliases, fase, plataforma, dificultad, mitre), tipos y enums correctos, slugs únicos globalmente, paridad entre `title` del frontmatter y H1 del body, formato MITRE `T\d{4}(\.\d{3})?`, vacío permitido en `mitre` sólo si fase es Fundamentos o Forense y DFIR, ausencia de sección `## Clasificación` en el body, y resolución cruzada de `related` (cada slug existe) y `learning_refs` (cada path existe en learning/ y contiene .md).
- Salida: `ERR <path>: <descripción>` por cada problema, código de salida 0/1.

### `scripts/build_indexes.py` (nuevo)
- Regenera los **29 INDEX.md hoja** desde frontmatter. Tabla `Técnica | MITRE | Dificultad | Plataforma`, ordenada alfabéticamente por nombre mostrado, con backlink correcto a cada fase (acentos preservados en "Análisis de Vulnerabilidades", "Explotación", etc.).
- Genera nuevo **`inventario/TOPICS.md`**: índice plano por slug con archivo, fase, plataforma, dificultad, aliases, related (como slugs) y learning_refs (con links a learning/).
- Genera nuevo **`inventario/meta/`** con vistas facetadas auto-generadas: `by-mitre.md`, `by-difficulty.md`, `by-platform.md`, `by-fase.md`. Cada una agrupa los 124 archivos por el valor del facet correspondiente.
- Idempotente: el marcador `<!-- AUTOGENERADO por scripts/build_indexes.py. NO editar a mano la tabla. -->` delimita la zona generada; la narrativa antes del marcador (H1 + descripción de la subcategoría) se preserva inalterada.
- Modo `--check` para integración con CI/git hooks: falla si los archivos están desactualizados sin escribirlos.

### Fixes derivados
- 22 archivos con título conteniendo `:` rompían el parsing YAML. Fix one-shot quotó los títulos: `title: "Análisis de Vulnerabilidades: SQL Injection (SQLi)"`. El script `migrate_frontmatter.py` ahora cita preventivamente cualquier scalar con caracteres YAML especiales (`:`, `#`, `&`, `*`, `!`, `|`, `>`, `%`, `@`, `` ` ``).
- 2 archivos de Fase 01 (`deteccion-waf.md`, `transparencia-certificados.md`) tenían title del frontmatter más corto que el H1 del body. Sincronizados al H1 (la versión larga es la canónica para humanos).

### Estado tras Sprint 2
- `python3 scripts/validate.py` → 124/124 OK.
- `python3 scripts/build_indexes.py --check` → up to date.
- Discoverabilidad LLM: queries por slug, fase, plataforma, dificultad y MITRE funcionan vía grep sobre frontmatter; vistas facetadas en `inventario/meta/` permiten lookup directo sin grep; TOPICS.md da una vista por tema cruzada.
- Pendiente sólo: enriquecimiento manual de aliases/related para topics frecuentes (búsqueda por sinónimo como "Kerberoasting" todavía no encuentra el archivo correspondiente porque sus aliases son auto-derivados de title).

## [2026-05-03] — Sesión 19c (Sprint 1: frontmatter YAML en Fases 02-08)

Continuación de la sesión 19b. Tras validar el patrón en Fase 01, se construyó un script de migración para procesar las fases 02-08 sin escribir frontmatter a mano por 111 archivos.

### Script `scripts/migrate_frontmatter.py` (nuevo)
- Parsea el bloque `## Clasificación` existente, extrae title (del H1), fase (split coma+espacio), plataforma, dificultad, y mitre (regex sobre todo el bloque MITRE para soportar multi-IDs en una línea o multilínea con bullets indentados).
- Deriva slug del nombre de archivo (sin extensión).
- Genera frontmatter YAML al inicio con aliases default `[title]`, related y learning_refs default `[]`.
- Elimina la sección `## Clasificación` del body.
- Idempotente: salta archivos que ya tienen frontmatter (los 13 de Fase 01).
- Permite `mitre: []` para contenido conceptual cuya fase incluye `Fundamentos` o `Forense y DFIR` (modelos teóricos, PICERL, fundamentos de redes/sistemas no tienen mapping limpio a MITRE).

### Migración aplicada
- 111 archivos migrados a frontmatter YAML (fases 02-08).
- 13 archivos saltados (Fase 01, ya migrada manualmente en sesión 19b).
- Total: 124 archivos técnicos con frontmatter, 0 con `## Clasificación` en body, 124 slugs únicos.

### Conflicto de slug resuelto
- `inventario/02-enumeracion/web/fingerprinting-tecnologias-web.md` colisionaba en slug con `inventario/01-reconocimiento/pasivo/fingerprinting-tecnologias-web.md` (mismo nombre de archivo en distintas fases). Renombrado vía `git mv` a `fingerprinting-tecnologias-web-activo.md` para alinear con la convención "base + modifier" descrita en AGENTS.md. Slug actualizado a `fingerprinting-tecnologias-web-activo`. Cross-link en el archivo pasivo y enlace en `02-enumeracion/web/INDEX.md` actualizados. `aliases` y `related` enriquecidos manualmente para este archivo en particular (incluye WhatWeb, httpx, Wappalyzer CLI; relacionado con la versión pasiva, banner-grabbing-http, deteccion-waf).

### Verificación
- `find inventario -name "*.md" -not -name INDEX.md -exec grep -l "^slug: " {} \; | wc -l` → 124.
- `find inventario -name "*.md" -not -name INDEX.md -exec grep -h "^slug: " {} \; | sort | uniq -d` → 0 duplicados.
- `grep -rl "^## Clasificación" inventario/` → 0 archivos.
- Distribución por plataforma: 12 Linux, 21 Windows, 37 Web, 6 Red, 48 Multi (suma 124).
- Queries facetadas funcionan: T1190 devuelve 10+ archivos web, intersección Avanzada+Web devuelve 5 archivos esperados, slugs con sustring `sqli` devuelve los 3 archivos relacionados (analisis-sqli, explotacion-sqli, explotacion-nosqli).

### Limitación conocida (deuda para enriquecimiento posterior)
- `aliases:` para los 111 archivos migrados por script contiene únicamente `[title]`. Búsquedas por sinónimo (ej. "Kerberoasting", "PtH") no encuentran los archivos correspondientes hasta que se enriquezcan a mano. Es una decisión consciente: el script no infiere aliases para no introducir ruido. La discoverabilidad por slug, fase, plataforma, dificultad y MITRE sí funciona.
- `related:` está vacío para los 111 archivos migrados por script. Las relaciones cross-fase (analisis-sqli ↔ explotacion-sqli, etc.) deben añadirse a mano en una pasada de enriquecimiento posterior.
- Sprint 2 (validate.py + build_indexes.py) sigue pendiente y detectará dangling refs cuando se enriquezca related.

## [2026-05-03] — Sesión 19b (Sprint 1 piloto: frontmatter YAML en Fase 01)

Continuación de la sesión 19. Sprint 1 del plan de discoverabilidad ejecutado en Fase 01 (Reconocimiento) como piloto antes de escalar a fases 02-08.

### TEMPLATE.md reescrito
- Frontmatter YAML añadido como bloque obligatorio al inicio (10 campos: title, slug, aliases, fase, plataforma, dificultad, mitre, related, learning_refs).
- Sección `## Clasificación` eliminada del body — el frontmatter es ahora la fuente única de verdad para la metadata.
- Comentario HTML al final ampliado: 10 notas que documentan cada campo del frontmatter, las reglas de pares cross-fase (slug base vs `<slug>-explotacion`), y las reglas de arrays siempre para `fase`/`mitre`.

### AGENTS.md actualizado
- Sección "Formato de cada Técnica" reescrita: ejemplo de bloque incluye frontmatter al inicio, tabla con tipo y obligatoriedad de cada campo, regla de slugs distintos para pares análisis/explotación cross-fase.
- "Cookbook de Búsqueda" actualizado con queries sobre frontmatter (`grep -lE "^slug: sqli$"`, `grep -lE "^mitre:.*\bT1190\b"`, intersecciones via xargs). Nota legacy para fases aún no migradas.
- Instrucciones del agente `revisor` ampliadas para validar frontmatter (campos requeridos, enums, arrays, formato MITRE, paridad title↔H1) y prohibir explícitamente la sección `## Clasificación` en el body.

### Fase 01 migrada (13 archivos)
- 5 archivos en `activo/`: descubrimiento-hosts, deteccion-waf, escaneo-puertos, escaneo-vulnerabilidades, fingerprinting-os-servicios.
- 8 archivos en `pasivo/`: dns-pasivo, fingerprinting-tecnologias-web, google-dorking, recoleccion-emails, shodan-censys, transparencia-certificados, wayback-machine, whois-registros-dominio.
- Cada archivo recibió frontmatter con slug único, aliases derivados del título y herramientas mencionadas, mitre como array (preservando sub-técnicas, ej. `[T1018, T1595.001]`), y `related:` con slugs de Fase 01 (algunos cross-fase como `enumeracion-dns` o `fingerprinting-tecnologias-web-activo` quedan pendientes de resolver hasta que las fases 02+ se migren — el validador del Sprint 2 los detectará si quedan dangling).
- Sección `## Clasificación` eliminada del body en los 13 archivos. Las otras 5 secciones (Descripción, Herramientas, Comandos, Contramedidas, Referencias) intactas.

### Queries de verificación (todas pasan)
- `grep -lE "^## Clasificación" inventario/01-reconocimiento/**/*.md` → 0 resultados.
- 13 slugs únicos en Fase 01.
- `grep -lE "^dificultad: Intermedia$"` y otras queries facetadas devuelven los archivos esperados.

### Pendiente para sesiones siguientes
- Sprint 1 fases 02-08 (~111 archivos restantes).
- Sprint 2: `scripts/validate.py` y `scripts/build_indexes.py` para garantizar que `related:` resuelve, slugs son únicos globalmente, y los 40 INDEX.md hoja se regeneran desde frontmatter.

## [2026-05-03] — Sesión 19 (Sprint 0 del plan de discoverabilidad LLM-first)

Primer sprint del plan de mejoras de discoverabilidad (`~/.claude/plans/ok-haz-un-plan-sequential-parnas.md`). Sprint 0 abarca naming + documentación; Sprints 1-2 (frontmatter YAML + tooling) llegan en sesiones siguientes.

### Renombrado
- `inventario/03-analisis-vulnerabilidades/web/analisis-sql-injection.md` → `analisis-sqli.md`. Razón: alinear con el par `04-explotacion/web/explotacion-sqli.md` y con la convención de naming recién documentada (acrónimo establecido en lugar de palabra completa). Era la única inconsistencia cross-fase del inventario tras auditar todos los pares topic. Historia preservada vía `git mv`. Referencias activas actualizadas en el INDEX correspondiente y en 5 writeups de `learning/portswigger/` (visible-error-based, blind-time-delays, blind-time-delays-info-retrieval, blind-out-of-band, sqli-filter-bypass-xml-encoding). Las menciones históricas en este CHANGELOG se dejaron intactas por fidelidad temporal.

### Documentación añadida en `AGENTS.md`
- **Sección "Convención de Naming de Archivos"**: codifica el patrón `<prefijo-acción>-<slug>.md`, mapeo de prefijo por fase (`analisis-` para 03, `explotacion-` para 04, `enumeracion-` para 02, `abuso-`/sin-prefijo en 05 según el caso, sin prefijo en 06-08), regla de "usar acrónimo establecido" con tabla de slugs canónicos (sqli, xss, csrf, ssrf, idor, lfi-rfi, xxe, ssti, jwt, nosqli, adcs), y regla de paridad entre pares cross-fase.
- **Sección "Cookbook de Búsqueda"**: ~10 patrones de grep que un agente puede ejecutar para localizar técnicas sin recorrer la jerarquía de INDEX (find por slug, grep por dificultad/plataforma/MITRE/fase/herramienta/autor de referencia). Anota que el cookbook cambiará tras la migración a frontmatter YAML.
- **Sección "Política `learning_refs`"**: define qué cuenta como writeup linkeable (directorio con `writeup.md` estructurado) vs scratch (scripts sueltos, wordlists, fragmentos de curso). Sirve de guía para el Sprint 1 del plan, cuando los archivos del inventario ganen el campo `learning_refs:` en frontmatter.

### Auditoría sin cambios
- Pares cross-fase verificados con `diff` entre `03/web` y `04/web`: SQLi era la única inconsistencia. `deserialization` ya estaba alineado. No hay otros pares que requieran rename.
- Contenido de `learning/`: clasificado en linkeable (10 labs PortSwigger + `tryhackme/abusingwindowsinternals/`) vs no-linkeable (8 directorios de scripts en TryHackMe + archivos sueltos). No se movió nada físicamente — la política de `learning_refs` filtra a nivel de referencias.

## [2026-05-03] — Sesión 18 (Mantenimiento de consistencia tras review crítico)

Sesión de mantenimiento estructural disparada por review crítico de un agente externo. Se auditó cada hallazgo contra el repo, se calibraron severidades, se discutió y aprobó la decisión arquitectónica de **secciones opcionales en TEMPLATE** en lugar de un template alterno para contenido conceptual, y se aplicaron todos los fixes derivados.

### Cambios estructurales en TEMPLATE.md
- **Secciones opcionales**: Herramientas, Comandos / Ejemplos y Contramedidas pasan a opcionales para contenido conceptual o metodológico (modelos teóricos, ciclos, marcos). Las técnicas y herramientas concretas las siguen requiriendo. Documentado en nota 9 del comentario.
- **Valores compuestos en Fase**: separador estandarizado a coma+espacio. Permitidos para herramientas/técnicas que genuinamente cruzan fases. Plataforma sigue estricta. Documentado en notas 7 y 8.
- **Nota sobre MITRE ATT&CK**: ampliada para reconocer la limitación conocida de ATT&CK en el dominio de seguridad de aplicaciones (CSRF, IDOR, race conditions sin mapping limpio). Se establece T1190 como ID por defecto defensible.

### Fixes aplicados al inventario
- **MITRE incorrectos corregidos** (T1190 con link al ATT&CK):
  - `analisis-csrf.md`: T1185 (Browser Session Hijacking, no aplica a CSRF) → T1190.
  - `analisis-idor.md`: T1213 (Data from Information Repositories, no aplica a IDOR) → T1190.
- **Valores compuestos migrados a sintaxis de coma+espacio**:
  - `enumeracion-kerberos.md`: `Enumeración / Post-explotación` → `Enumeración, Post-Explotación`.
  - `bloodhound.md`: `Reconocimiento | Post-Explotación` → `Reconocimiento, Post-Explotación`. `Plataforma: Windows | Linux (interfaz)` → `Plataforma: Windows` (la nota cross-plataforma sobre GUI/agentes movida a Descripción, que es donde corresponde según TEMPLATE nota 7).
- **Acentos corregidos en 14 archivos de `01-reconocimiento/`** (toda la fase 1, escrita en algún momento sin acentos y nunca normalizada). Headers (`Descripción`, `Clasificación`) y cuerpo entero. Aplicado vía sed con script de patrones de alta confianza (palabras técnicas en español que casi siempre llevan acento). Tres pasadas, residuales finales (`deteccion`, `enumeracion`, `recoleccion`) son nombres de archivo en INDEX.md y son correctos así.
- **Referencias de libros del directorio `referencias/` añadidas a 5 archivos** que sólo citaban libros externos:
  - `modelo-osi-tcp-ip.md`: + Casad (TCP/IP in 24 Hours).
  - `volatility-memoria.md`, `picerl.md`, `artefactos-windows-host.md`: + Johansen (Digital Forensics and Incident Response).
  - `analisis-estatico-dinamico.md`: + Harper et al. (Gray Hat Hacking) por sus capítulos de análisis de malware.

### Consolidación de duplicados
- **DNS**: `01-reconocimiento/activo/enumeracion-dns.md` borrado. Su contenido único (NSEC walking, DNS cache snooping, amass active mode, ldns-walk como herramienta) se mergeó dentro de `02-enumeracion/red/enumeracion-dns.md` en una nueva subsección "Técnicas avanzadas". Las contramedidas correspondientes (NSEC3, limitar recursión, rate limiting) añadidas al bloque de defensas. INDEX.md de reconocimiento activo actualizado con nota redirigiendo al archivo canónico de enumeración. Razón estructural: la enumeración DNS activa (consultas directas al DNS del objetivo) es operacionalmente fase 2 (Enumeración), no fase 1 (Reconocimiento). El reconocimiento DNS pasivo (sin tocar al objetivo) sigue en `01-reconocimiento/pasivo/dns-pasivo.md`.
- **Fingerprinting**: ambos archivos (`01-reconocimiento/pasivo/` y `02-enumeracion/web/`) **reescritos completos** para delinear claramente pasivo vs activo. La versión pasiva enfoca BuiltWith, Wappalyzer extensión, Stackshare, Retire.js sobre JS local descargado, OSINT vía shodan/censys. La versión activa enfoca WhatWeb, httpx, Wappalyzer CLI, nmap NSE, curl probing, detección activa de Kubernetes/Docker/Envoy. Cross-references explícitas en ambos. Acentos arreglados en la versión activa.

### Documentación
- **AGENTS.md**: párrafo de descripción del inventario actualizado para reflejar las dos modalidades de uso del TEMPLATE (técnica concreta vs contenido conceptual) y la sintaxis de valores compuestos en Fase. Conteo (165) sigue siendo correcto: borrar el DNS duplicado y no añadir nada nuevo deja el conteo en 165 (124 técnicas + 40 INDEX + 1 TEMPLATE), igual que lo declarado.

### Hallazgos adicionales descubiertos durante la auditoría (no flageados por el review)
- **MITRE incorrecto en `inventario/03-analisis-vulnerabilidades/web/INDEX.md`**: el INDEX seguía mostrando T1185 para CSRF y T1213 para IDOR aunque los archivos de detalle ya estaban corregidos. Síntoma del review original que se quedó en archivos individuales sin auditar índices. Corregido a T1190 en ambos.
- **4 archivos más con compound values en Fase usando separadores antiguos** que el review no flagueó (sólo había revisado 2 archivos):
  - `02-enumeracion/servicios/enumeracion-docker.md`: `Enumeración / Explotación` → `Enumeración, Explotación`.
  - `02-enumeracion/servicios/enumeracion-kubernetes.md`: ídem.
  - `06-frameworks-herramientas/burp-suite/configuracion-uso-avanzado.md`: `Análisis de Vulnerabilidades | Explotación` → coma.
  - `06-frameworks-herramientas/metasploit/metasploit-avanzado.md`: 3 fases listadas con `|` → coma.
- **1 archivo con paréntesis explicativos en Plataforma** que el review no flagueó:
  - `02-enumeracion/servicios/enumeracion-ldap.md`: `Multi (principalmente Windows/Active Directory)` → `Multi`. La explicación de uso primario en Windows movida a Descripción.

### Patrón observado en el review
El review externo identificó correctamente 6 categorías de inconsistencia. Tras auditar contra el repo: 5 fixes factuales correctos, 1 caso (compound values en Fase/Plataforma) donde la "violación del template" era en realidad un síntoma de que el template no soportaba la realidad. Lección operacional: **antes de normalizar la realidad al template, comprobar si el template captura correctamente los casos legítimos**. La iteración debe ser bidireccional.

Adicionalmente, **el review tuvo coverage parcial**: encontró 2/6 archivos con compound values pero se le escaparon 4 más, y no auditó los INDEX.md (donde quedaron 2 MITRE incorrectos). Lección de meta-review: cuando un agente flaguea casos representativos de un patrón, validar que los flageados son exhaustivos antes de cerrar la auditoría. La auditoría de mi propio review encontró el doble de instancias del mismo patrón.

### Segunda iteración de review residual
Tras los fixes anteriores, segundo review crítico identificó tres hallazgos residuales:
- **TEMPLATE.md no listaba `Fundamentos` ni `Forense y DFIR` como valores válidos de Fase**, aunque archivos legítimos los usan (07-fundamentos, 08-forense-dfir). Solución: ampliar la lista en línea 7 y la nota 8 del comentario para reconocer las dos categorías de soporte como valores de Fase legítimos. Documentado con ejemplos.
- **AGENTS.md tenía un ejemplo de formato sin acentos** (`Tecnica`, `Descripcion`, `Clasificacion`, `Basica`) violando la propia regla de ortografía declarada dos líneas antes. El ejemplo además usaba `|` para compound Fase, sintaxis ya prohibida por el template. Reescrito completo con acentos correctos y nota explícita sobre compound con coma + perfil "contenido conceptual" con secciones reducidas.
- **Instrucciones del agente `revisor` y `redactor` decían "7 secciones del formato"** sin reconocer que el TEMPLATE ahora permite secciones reducidas para contenido conceptual. Reescrito para diferenciar perfiles ("técnicas concretas: 7 secciones; conceptual: 4 obligatorias + custom") y añadir 2 reglas de revisión nuevas (Fase con compound legal, ortografía del cuerpo).

Hallazgo extra de mi auditoría del review residual (no flageado por el agente): **AGENTS.md tenía 23+ palabras sin acentos repartidas por todo el archivo**, no sólo en el ejemplo de la línea 189. El review se quedó en el caso más visible. Aplicado el script sed completo, además de fixes manuales en `Edicion`, `Estandar`, `Tactica`, `taxonomia`, `precision`, `sintacticamente`, `publicacion`, `logicas`. AGENTS.md ahora 100% en español con ortografía correcta.

Patrón confirmado de la sesión: cada review identifica menos del 100% de instancias del patrón que detecta. **La auditoría tras un review siempre debe extender el patrón flageado a archivos no mencionados.**

## [2026-05-03] — Sesión 17 (Lab PortSwigger XSS stored en onclick con bypass via HTML entity)

Cuarto lab de la serie XSS Contexts y primer **stored** del path. Cambio de tipo (reflected → stored) y de contexto (literal JS dentro de `<script>` → atributo HTML event handler `onclick`). Las protecciones declaradas son las mismas que el lab "sq + backslash escaped" reflected (`<>"` HTML-encoded, `'` escapado, `\` escapado), pero el contexto destino abre una asimetría nueva: el atributo HTML pasa por **HTML decoding antes de pasar al motor JS**, así que entidades como `&apos;` aterrizan en el filtro como texto inocuo (seis chars sin `'` literal) y el navegador las decodifica a `'` viva justo antes de ejecutar. El bypass es estructuralmente idéntico al de SQLi WAF via XML hex entities (sesión 13). Solved al primer intento del payload `http://foo?&apos;-alert(1)-&apos;`.

### Añadido
- **`learning/portswigger/stored-xss-onclick-html-entity-bypass/`** — décimo writeup de `learning/portswigger/`, cuarto de XSS:
    - `writeup.md` (8 secciones): contexto exacto del reflejo (Website URL del comentario aterriza dentro de `tracker.track('...')` en `onclick` de un `<a id="author">`), explicación de la asimetría doble-decoding (HTML attribute decoding precede al parser JS, filtro server-side opera sobre input crudo), sondeo único confirmando que `&apos;` pasa intacto el filtro y aparece como `'` literal en el DOM, payload completo con trace paso a paso (filtro, HTML emitido, HTML decoding, parsing JS), explicación del operador `-` como elección minimalista para evaluar `alert` como subexpresión sin SyntaxError (vs alternativas `||`/`,`/backticks), contramedidas con énfasis en el patrón estructural correcto (atributo `data-*` + `addEventListener`, NO event handler inline), orden correcto de escape (HTML-decode antes de escape JS para cerrar la asimetría), validación de URL como tipo, CSP sin `'unsafe-inline'`, allow-list vs deny-list. Cross-link al writeup hermano del SQLi WAF bypass que usa el mismo principio.
    - `solved.png`: confirmación visual del lab solved.

### Patrón transversal observado
- **Asimetría parser/encoding** se confirma como vector recurrente de bypass cross-vulnerabilidad: SQLi via XML hex entities (sesión 13), XSS via HTML entities en event handler (este lab). El principio: el filtro inspecciona un formato, un parser intermedio lo decodifica antes de llegar al ejecutor, y el filtro nunca ve los meta-caracteres en su forma activa. Defensa común: normalizar el input al formato del ejecutor antes de aplicar reglas de filtrado.

## [2026-05-02] — Sesión 16 (Lab PortSwigger XSS JS string con angle/double-quotes encoded y single-quotes escaped)

Tercer lab de la serie XSS Contexts y complemento exacto del anterior. Mismo contexto JS-en-HTML (`var searchTerms = '...'` dentro de un `<script>` inline), pero con set de escapes invertido: `<>"` HTML-encoded (cierra la salida vía `</script>`), `'` escapado (cierra la salida directa), pero **`\` no escapado** (abre la ruta del bypass de backslash que el lab anterior cerraba). Solved al primer intento del payload. Los dos labs juntos demuestran el principio "escape consciente del contexto que cubre todos los meta-caracteres".

### Añadido
- **`learning/portswigger/reflected-xss-js-string-angle-quotes-encoded/`** — noveno writeup de `learning/portswigger/`, tercero de la categoría XSS:
    - `writeup.md` (8 secciones): tabla comparativa con el lab "sq + backslash escaped" mostrando cómo cada lab cierra justo la salida que el otro abre, los tres sondeos atómicos (`<` HTML-encoded, `'` escapado a `\'`, `\` literal sin duplicar), explicación detallada del bypass de "escape de escape" (atacante prepende `\` antes de su `'`, el filtro mete su propio `\` de escape, los dos backslashes se neutralizan entre sí en el parser JS dejando libre la `'` siguiente para cerrar el string), trace token a token del parser JS sobre `'\\';alert(1)//'`, variante oficial de PortSwigger con operador `-` en vez de `;` y por qué ambas funcionan, contramedidas con énfasis en el orden correcto de escape (primero `\`, después `'`/`"`) y el patrón idiomático `JSON.parse(json_encode(input))`, anti-patrón observado en el lab (escapar `'` sin escapar primero `\`).
    - `solved.png`: confirmación visual del lab solved.

## [2026-05-02] — Sesión 15 (Lab PortSwigger XSS en JS string con ' y \\ escapados)

Segundo lab de la serie XSS Contexts: reflejo dentro de `var searchTerms = '...'` en un bloque `<script>` inline, con escape activo de `'` y `\`. Solved al primer intento del payload. Valor pedagógico: la idea de **dos parsers en serie** (HTML + JS) que se atacan en capas distintas. El filtro escapa la sintaxis del parser interno (JS string) pero deja intacta la del externo (HTML script data state), lo que permite romper el bloque `<script>` con `</script>` literal antes de que el motor JS vea siquiera el contenido. Primer writeup del repo escrito **sin em-dashes** por preferencia explícita del usuario.

### Añadido
- **`learning/portswigger/reflected-xss-js-string-sq-backslash-escaped/`** — octavo writeup en `learning/portswigger/`, segundo de la categoría XSS:
    - `writeup.md` (8 secciones): contexto exacto del reflejo (`<script>` inline con `var searchTerms = '...'` + `document.write` que renderiza un `tracker.gif`), sondeos atómicos confirmando los dos escapes (`'` a `\'`, `\` a `\\`), tabla de payloads "desde dentro" demostrando por qué el doble escape cierra todas las salidas internas (incluido el bypass clásico `\';...//` que neutraliza el escape de comilla con un backslash propio cuando sólo hay protección de `'`), explicación detallada del modelo "dos parsers en serie" (HTML "script data state" del WHATWG vs motor JS) y la asimetría que se explota (filtro server-side escapa lo que parece sintaxis JS, deja intacto lo que es sintaxis HTML del bloque contenedor), trace paso a paso del parser HTML procesando `</script><script>alert(1)</script>` (cierra primer script, motor JS recibe string sin cerrar y lanza SyntaxError silencioso, segundo script ejecuta alert), visualización ASCII del corte HTML/JS, contramedidas con foco en patrones idiomáticos (data-* attributes + dataset, JSON.parse con json_encode, escape combinado JS+HTML escapando `<` y `>` además de `'` y `\`) más nota sobre el anti-patrón de elegir una capa de escape en vez de combinar las dos.
    - `solved.png`: confirmación visual del lab solved.

### Cambio de estilo
- Primer writeup que evita em-dashes (`—`) por preferencia del usuario, documentada en su `CLAUDE.md` global. Los seis writeups previos los siguen usando, no se tocaron retroactivamente.

## [2026-05-02] — Sesión 14 (Lab PortSwigger XSS canonical link tag — primer lab de XSS)

Cambio de familia: de SQLi a **XSS reflejado en contexto de atributo HTML**. Primer lab de la serie XSS Contexts. Solved al primer intento del payload, pero el valor pedagógico estuvo en el diagnóstico previo: **una rareza del Elements panel de Chrome** ocultó que el `href` del `<link rel="canonical">` se delimitaba con apóstrofos en el HTML crudo del servidor. La interpretación correcta sólo aparece con View Source / Network Response.

### Añadido
- **`learning/portswigger/reflected-xss-canonical-link-tag/`** — séptimo writeup en `learning/portswigger/`, primero de la categoría XSS:
    - `writeup.md` (8 secciones): objetivo y restricciones del contexto (`<link>` en `<head>`, filtro escapa `<>` pero no `'`), reconocimiento con foco en la **trampa del Elements panel de Chrome** (renormaliza atributos a `"..."` y oculta el delimitador real de `'...'` del servidor), recomendación de View Source/Network Response como ground-truth para XSS de atributo, diseño del payload alrededor de **`accesskey` + `onclick`** como par para activar elementos no visibles vía atajo de teclado (tabla de combinaciones por OS/navegador), explicación detallada del parsing apóstrofo a apóstrofo del HTML crudo (cada `'` como toggle abrir/cerrar atributo, 6 apóstrofos → 3 atributos legítimos en el DOM final), payload `'accesskey='x'onclick='alert(1)`, contramedidas con foco en output encoding context-aware (no basta `<>`, hay que escapar el delimitador del atributo) + CSP estricta + no reflejar query string en canonical URLs.
    - `solved.png`: confirmación visual del lab solved.



Sesión continuando la serie SQLi de PortSwigger: cambio de tipo de lab de blind a **UNION-based con WAF + bypass via XML hex entities**. Solved al primer intento. Aprovechamos para añadir al inventario dos huecos nuevos: la distinción numeric/string SQLi y la categoría completa de WAF bypass (encoding asimétrico + bypasses a nivel SQL).

### Añadido
- **`learning/portswigger/sqli-filter-bypass-xml-encoding/`** — sexto writeup en el directorio `learning/portswigger/`. Construido iterativamente:
    - `writeup.md` (10 secciones): objetivo y cambio de patrón (de cookie a body XML, de blind a UNION-based con WAF), recon del endpoint `/product/stock` con `Content-Type: application/xml`, **sondeo aritmético `3-1` para confirmar numeric SQLi sin tocar keywords del WAF** (técnica didácticamente clave: pasa por debajo del radar del WAF de patrones), confirmación del WAF con respuestas 403 "Attack detected" en `'` y `UNION`, explicación de la asimetría WAF-vs-parser (WAF inspecciona wire format, backend ve XML parseado) que habilita el bypass, construcción del bypass mínimo encodeando sólo la primera letra de las keywords (`&#x55;NION &#x53;ELECT`) más las comillas (`&#x27;`), validación con `UNION SELECT NULL` (200 OK + body con `null`) y descubrimiento bonus de que el endpoint imprime todos los rows del result set (permite extraer toda la tabla en una request), extracción con `username||'~'||password FROM users`, login admin, contramedidas específicas (parametrización, validación de tipo numeric en valores XML, WAFs que parsean el formato antes de aplicar reglas, allow-list).
    - `solved.png`: confirmación visual del lab solved.

### Actualizado
- **`inventario/03-analisis-vulnerabilidades/web/analisis-sql-injection.md`**:
    - **Bloque nuevo "Sondeo previo — numeric vs string SQLi"** al inicio de "Comandos / Ejemplos", explicando la distinción y proponiendo el test aritmético (`3-1`) y el test de comilla como sondeos complementarios. Útil contexto antes de los 6 tipos de inyección.
    - **Nueva sección 6 "WAF Bypass — Encoding asimétrico"** después de load_file. Documenta el patrón general (WAF inspecciona wire format, parser decodea), tabla de esquemas de encoding por formato del body (XML entities, JSON unicode escapes, URL-encoding, multipart Content-Transfer-Encoding, gzip), ejemplo XML completo con bypass mínimo vs agresivo, y bloque de bypasses a nivel SQL (comentarios inline `UN/**/ION`, whitespace alternativo `%09`/`%0a`/`/**/`, equivalencias semánticas `&&`/`||`/`MID`/`IIF`). Cierra con heurística de orden de prueba.
    - Referencias ampliadas con el nuevo writeup.
- **`inventario/04-explotacion/web/explotacion-sqli.md`**:
    - Sondeo aritmético `3-1` añadido al bloque "Pruebas manuales básicas" como primer test antes del bypass clásico de login.
    - Bloque XML hex entities bypass añadido después del bloque OOB, con bypass mínimo vs agresivo + bloque adicional de bypasses SQL-level (comentarios inline, whitespace alternativo, equivalencias semánticas) y heurística de orden de prueba.
    - Referencias ampliadas con el nuevo writeup.

## [2026-04-29] — Sesión 12 (Lab PortSwigger OOB + categoría OOB en inventario)

Sesión continuando la serie de blind SQLi: lab de **out-of-band interaction** (Oracle, XXE via `xmltype`). El lab no se cerró como **Solved** porque PortSwigger Academy bloquea outbound hacia cualquier dominio distinto de `*.oastify.com` (Burp Pro Collaborator, no disponible). El conocimiento técnico y el diagnóstico se capturan igualmente: la categoría OOB queda añadida al inventario como cuarta familia blind, y el writeup documenta tanto la técnica como la limitación operacional encontrada.

### Añadido
- **`learning/portswigger/blind-sqli-out-of-band/`** — quinto writeup en el directorio `learning/portswigger/`. No solved (limitación operacional), pero pedagógicamente valioso:
    - `writeup.md` (9 secciones): objetivo, motivo del cambio de motor a Oracle (XXE via `xmltype` es Oracle-específico), tabla de primitivas OOB por motor, setup de **interactsh-client** como receptor OAST gratuito (alternativa a Burp Collaborator), construcción del payload Oracle XXE pieza por pieza, **diagnóstico sistemático** ante la falta de interacciones (descarte de Burp HTTP/2 con curl, descarte de `+` vs `%20`, descarte de XXE-específico probando `UTL_HTTP.REQUEST` y `UTL_INADDR.GET_HOST_ADDRESS`, descarte de cookie no procesada), hallazgo final del **firewall de PortSwigger Academy que sólo permite `*.oastify.com`** (citado del statement del lab que pasamos por alto al empezar — lección meta sobre leer las notas completas antes de inyectar), conclusión de que el lab requiere Burp Pro, contramedidas específicas de OOB (egress filtering en el host de la DB, deshabilitar resolvers de entidades externas en parsers XML, privilegios mínimos sobre `UTL_HTTP`/`UTL_INADDR`/`xp_dirtree`).

### Actualizado
- **`inventario/03-analisis-vulnerabilidades/web/analisis-sql-injection.md`** — **nueva sección 4 "Inyección Fuera de Banda (Out-of-Band / OAST)"** insertada entre time-blind y load_file (antes el archivo cubría sólo error/boolean/time + load_file; OOB era un hueco evidente). Incluye: cuándo aplica (queries async fire-and-forget que cierran los tres canales clásicos), tabla de primitivas OOB por motor (Oracle XXE+UTL_HTTP+UTL_INADDR+DBMS_LDAP, MS SQL `xp_dirtree`, MySQL `LOAD_FILE`+`OUTFILE` Windows, PostgreSQL `COPY TO PROGRAM`), ejemplo Oracle XXE completo con explicación del orden de evaluación (`xmltype()` resuelve la entidad antes de llegar a `EXTRACTVALUE`), tabla de receptores OAST (Burp Collaborator vs interactsh vs DNSLog vs servidor propio) con coste y caso de uso, nota operacional sobre allowlists de OAST (PortSwigger Academy `*.oastify.com` only). Referencias ampliadas con el nuevo writeup.
- **`inventario/04-explotacion/web/explotacion-sqli.md`** — bloque OOB añadido a "Pruebas manuales", paralelo a los bloques error-based y time-based de sesiones anteriores. Cubre Oracle XXE + alternativas, MS SQL `xp_dirtree`, MySQL Windows. Incluye ejemplo URL-encodeado del payload XXE para cookie, comando de instalación de `interactsh-client` y nota sobre allowlists OAST en entornos de prácticas. Referencias actualizadas con los dos writeups que faltaban (info-retrieval y out-of-band).

## [2026-04-29] — Sesión 11 (Lab PortSwigger time-delays info retrieval + script de extracción)

Sesión continuando la serie de blind SQLi: del lab anterior (sólo provocar retardo) al lab "info-retrieval" donde hay que **extraer la password** de `administrator` por inferencia carácter a carácter via `CASE WHEN ... pg_sleep ... ELSE pg_sleep(0) END`. Pivote operacional clave: descartar Burp Intruder (1 thread en Community → ~6 min) y scriptear la extracción en Python con `ThreadPoolExecutor` (~1 min real medido).

### Añadido
- **`learning/portswigger/blind-sqli-time-delays-info-retrieval/`** — cuarto writeup en el directorio `learning/portswigger/`. Construido iterativamente durante la sesión:
    - `writeup.md` (8 secciones): objetivo y diferencia con el lab base, **validación de las dos ramas del `CASE` antes de extraer** (test `(1=1)` → 10s, test `(1=2)` → baseline; sin esto los falsos positivos invalidarían toda la extracción), determinación de longitud (`LENGTH(password)=20` → 10s confirma 20 chars), narrativa del pivote Burp Intruder → script Python con análisis del coste real (~6 min Community vs 67s medidos con 10 workers, sleep=5s, threshold=3s) y discusión de por qué no escala linealmente (serialización de `pg_sleep` en el pool de conexiones de la DB), resumen con diagrama Mermaid y contramedidas específicas para extracción time-based (`statement_timeout` corto como contramedida quirúrgica, rate limiting, decorrelación tiempo-de-respuesta vs tiempo-de-backend).
    - `extract.py`: script funcional autocontenido (~80 líneas). Usa `requests` + `concurrent.futures.ThreadPoolExecutor`, encodea la cookie con `urllib.parse.quote_plus` (resuelve `;` → `%3B`, `'` → `%27`, espacios → `+` de un golpe), imprime hits en streaming, parametrizable por `--url`, `--session` y `--workers`.
    - `solved.png`: confirmación visual del lab resuelto (login con la password extraída `jyuepelyogm45rdshesl`).

### Actualizado
- **`inventario/04-explotacion/web/explotacion-sqli.md`** — añadida nota operacional al final del bloque time-based: paralelismo en extracción time-based, limitación de Burp Community (1 thread), patrón `requests + ThreadPoolExecutor` con cuello de botella en el pool de conexiones de la DB, link al writeup como implementación de referencia.

## [2026-04-29] — Sesión 10 (Lab PortSwigger + enriquecimiento SQLi time-based)

Sesión de aprendizaje guiada paso a paso resolviendo el lab de PortSwigger **"Blind SQL injection with time delays"**, con captura del conocimiento operativo derivado en el inventario.

### Añadido
- **`learning/portswigger/blind-sqli-time-delays/`** — tercer writeup en el directorio `learning/portswigger/`. Construido iterativamente durante la sesión:
    - `writeup.md` (8 secciones): objetivo, baseline cuantificado (~185ms estable), descarte explícito de canales más cómodos (test `'` suelto sin error reflejado → no error-based; `AND '1'='1` vs `AND '1'='2` con respuestas idénticas → no boolean-based) que justifica el salto a tiempo, payload final con stacked queries (`x'%3BSELECT+pg_sleep(10)--`) con explicación pieza por pieza, **detalle didáctico del `;` como delimitador de cookies y la necesidad de URL-encodearlo como `%3B`** (gotcha específico de inyectar en headers Cookie), tabla de primitivos de retardo por motor (PG `pg_sleep`, MySQL `SLEEP`, MS SQL `WAITFOR DELAY`, Oracle `dbms_pipe.receive_message`, SQLite con queries pesadas), variantes equivalentes (concat `||`, cláusula `AND`), resumen con diagrama Mermaid y contramedidas (statement_timeout, deshabilitar multi-statement, monitoreo de latencia anómala).
    - `solved.png`: confirmación visual del lab resuelto al primer intento.

### Actualizado
- **`inventario/03-analisis-vulnerabilidades/web/analisis-sql-injection.md`** — sección 3 "Inyección Ciega Basada en Tiempo" reescrita y ampliada. Antes solo listaba MySQL `SLEEP` y el patrón complejo PostgreSQL `CASE WHEN ... pg_sleep ... ELSE pg_sleep END`; ahora documenta tabla de primitivos por motor (PG/MySQL/MSSQL/Oracle/SQLite), las tres formas de inyectar el sleep (stacked queries `;`, concat `||`, cláusula `AND`) según qué tolere el sink, el patrón `CASE WHEN` reservado explícitamente para inferencia bit a bit, ejemplos de inferencia en PG/MySQL/MS SQL, y nota sobre el `;` URL-encoded cuando el sink es header Cookie. Mención del baseline como pre-requisito metodológico. Referencias ampliadas con el nuevo writeup.
- **`inventario/04-explotacion/web/explotacion-sqli.md`** — bloque "Pruebas manuales básicas" extendido con un nuevo bloque dedicado a payloads time-based, paralelo al de error-based añadido en sesión 9. Cubre los 5 motores principales, payload de inferencia con `CASE WHEN`, gotcha del `;` URL-encoded en cookies, y ejemplo de `sqlmap --technique=T --time-sec=5`. Referencias con enlace al writeup.

## [2026-04-29] — Sesión 9 (Lab PortSwigger + enriquecimiento SQLi error-based)

Sesión de aprendizaje guiada paso a paso resolviendo el lab de PortSwigger **"Visible error-based SQL injection"**, con captura del conocimiento operativo derivado en el inventario.

### Añadido
- **`learning/portswigger/visible-error-based-sql-injection/`** — segundo writeup en el directorio `learning/portswigger/`. Construido iterativamente durante la sesión:
    - `writeup.md` (8 secciones): objetivo, provocación del primer error con la nota didáctica `'` solo vs `' --` (la trampa típica donde el `--` cierra y comenta — no rompe — la query), salto de error de sintaxis a exfiltración con la técnica `CAST(<subquery> AS int)`, descubrimiento del **truncado de la cookie a 60 chars server-side** y workaround con concatenación `||` para meter el `CAST` dentro del string del `WHERE`, lectura de `users.password` con `LIMIT 1`, login como administrator, resumen de la cadena con diagrama Mermaid, contramedidas y referencias APA.
    - `solved.png`: confirmación visual del lab resuelto.

### Actualizado
- **`inventario/03-analisis-vulnerabilidades/web/analisis-sql-injection.md`** — sección 1 "Inyección Basada en Error" reescrita y ampliada. Antes solo listaba el clásico MySQL `COUNT/GROUP BY/FLOOR(RAND())`; ahora documenta el primitivo más limpio (`CAST` en PostgreSQL/SQLite que vuelca el valor en `ERROR: invalid input syntax for type integer`) con sus equivalentes por motor (`CONVERT` en MS SQL, `TO_NUMBER` en Oracle, `extractvalue()` XPath en MySQL), añade la variante con concatenación `||` para casos con límite de longitud en el punto de inyección, y deja el payload `COUNT/GROUP BY` como fallback explícito. Referencias ampliadas con PortSwigger Blind SQLi y enlace al writeup como evidencia.
- **`inventario/04-explotacion/web/explotacion-sqli.md`** — bloque "Pruebas manuales básicas" extendido de un solo payload (MySQL clásico) a cinco variantes comentadas: PostgreSQL/SQLite con `CAST AND` clásico, PostgreSQL/Oracle/SQLite con concatenación `||`, MS SQL con `CONVERT/TOP 1`, MySQL con `extractvalue`, y el `COUNT/GROUP BY` original como fallback. Referencias con enlace al writeup.

## [2026-04-28] — Sesión 8 (Lab PortSwigger + enriquecimiento CSRF)

Sesión de aprendizaje guiada paso a paso resolviendo el lab de PortSwigger **"SameSite Lax bypass via cookie refresh"**, con captura del conocimiento operativo derivado en el inventario.

### Añadido
- **`learning/portswigger/samesite-lax-bypass-via-cookie-refresh/`** — primer writeup en el directorio `learning/portswigger/`. Construido iterativamente durante la sesión:
    - `writeup.md` (~600 líneas, 10 secciones): objetivo, reconocimiento del flujo OAuth con diagrama de secuencia Mermaid y 5 observaciones extraídas del Burp history, fundamentos de CSRF con verificación de los 3 ingredientes, explicación de SameSite (los 3 modos + excepción Lax+POST de Chrome), construcción incremental del exploit en 4 versiones (V1 ingenuo → V4 con click programático en `onload`), entrega, troubleshooting, contramedidas y referencias APA.
    - `http_history.xml` y `change-email.xml`: capturas Burp del flujo OAuth y del POST legítimo, citadas como evidencia en el writeup.
    - `exploit.html`: payload V4 final listo para subir al exploit server.
    - `solved.png`: confirmación visual de que el lab quedó resuelto al primer intento.

### Actualizado
- **`inventario/03-analisis-vulnerabilidades/web/analisis-csrf.md`** — añadida sección **Bypasses de SameSite** con dos técnicas documentadas (ventana Lax+POST de 2 min en Chrome, cookie refresh via OAuth/SSO) y referencia breve a otros bypasses conocidos (method override, client-side redirect, sibling domain). Sección de Contramedidas reforzada con guía explícita: tokens anti-CSRF como defensa principal (no `SameSite`), fijar `SameSite` explícito para evitar el modo default que activa Lax+POST, no emitir cookies nuevas en endpoints navegables sin gesto del usuario. Referencias ampliadas con PortSwigger, Chromium SameSite Updates, MDN y OWASP CSRF Cheat Sheet.

## [2026-04-28] — Sesión 7 (Pasada de consistencia)

Auditoría y limpieza del warehouse para dejarlo en estado íntegro y honesto, motivada por el descubrimiento de **96 archivos** con referencias rotas a `notas-md/` (directorio que ya no existe en disco). El objetivo: que cualquier agente que consulte el inventario reciba información verificable y un mapa de navegación íntegro.

### Limpieza
- **Refs rotas a `notas-md/` eliminadas en 96 archivos del inventario**. `notas-md/` fue el export Notion usado para bootstrapear el inventario en 2025; el contenido relevante ya está absorbido en los archivos `analisis-*.md` / `explotacion-*.md` / etc. Las refs apuntando a `notas-md/HNotes/...` se eliminaron mecánicamente con `sed '/^- Notas del proyecto: notas-md\//d'`, preservando intactas las referencias bibliográficas a libros, MITRE, HackTricks y demás. Las 2 refs vivas a `learning/tryhackme/...` (verificadas como archivos existentes) se conservaron.
- **`inventario/TEMPLATE.md`** — removida la línea de ejemplo `Para notas: Notas del proyecto: notas-md/ruta/al/archivo.md` del comentario para redactor, evitando que se propague el patrón muerto a archivos nuevos.

### Actualizado
- **`AGENTS.md`** — reescrita la sección `Fuentes de Información` para reflejar la realidad actual. La nueva sección 1 describe `inventario/` como fuente canónica (165 archivos) con la jerarquía de 3 niveles de `INDEX.md` explícitamente documentada (root → fase → subcategoría). Se añadió una nota histórica explicando el origen y archivado de `notas-md/`. Actualizadas además: protocolo de búsqueda local (paso 1), `Heurísticas de Prioridad` (Prioridad 3), `Resolución de Conflictos` (duplicados), instrucciones del agente `investigador`, y `Paso 1 — Investigación` del Workflow Probado, todas para dejar de referenciar el directorio inexistente.

### Añadido
- **`inventario/07-fundamentos/sistemas/INDEX.md`** — añadida fila `Windows API para Hacking | Intermedia` que existía en el dir desde antes pero no estaba listada en el INDEX.
- **`inventario/07-fundamentos/compliance/INDEX.md`** — creado placeholder informativo enumerando tópicos esperados (CVSS v3/v4, OWASP ASVS, NIST CSF, ISO 27001/27002, MITRE D3FEND, GDPR). El dir existía vacío sin INDEX, rompiendo el contrato de la jerarquía navegable.
- **`inventario/07-fundamentos/INDEX.md`** — añadida entrada para la subcategoría `Compliance` marcada como `(pendiente de contenido)`.

### Verificado post-pass
Auditoría de integridad completa, todos los chequeos limpios:
- 0 referencias rotas a `notas-md/` en el inventario.
- 0 desincronizaciones tier-3 (todos los archivos `*.md` están listados en su INDEX de subcategoría).
- 0 desincronizaciones tier-2 (todas las subcategorías están listadas en el INDEX de su fase).
- 0 directorios sin INDEX.
- 166 archivos `.md` totales (165 previos + 1 nuevo en compliance).

## [2026-04-07] — Sesión 6 (FINALIZACIÓN DEL PROYECTO)

### Añadido
- **Fase 06 - Frameworks y Herramientas** — 4 guías avanzadas:
    - **burp-suite/**: `configuracion-uso-avanzado.md` (Scope, Intruder, Macros de sesión).
    - **metasploit/**: `metasploit-avanzado.md` (Workspaces, Resource files, Post-exploitation).
    - **powershell-empire/**: `empire-framework.md` (Listeners, Stagers, C2 workflow).
    - **otros/**: `bloodhound.md` (SharpHound, Graph theory, AD attack paths).
- **Fase 07 - Fundamentos** — 4 guías base:
    - **redes/**: `modelo-osi-tcp-ip.md` (PDU, Three-Way Handshake, Comandos de diagnóstico).
    - **sistemas/**: `linux-arquitectura-permisos.md` (FHS, Permisos rwx, SUID/SGID, Gestión de procesos).
    - **sistemas/**: `windows-arquitectura-ad.md` (Procesos críticos,lsass, Kerberos/NTLM, Fundamentos AD).
    - **criptografia/**: `hashing-codificacion.md` (Diferencias Codificación/Hash/Cifrado, Algoritmos, Herramientas).
- **Fase 08 - Forense y DFIR** — 4 guías de investigación:
    - **analisis-forense/**: `artefactos-windows-host.md` (Prefetch, ShimCache, LNK, Eric Zimmerman's tools).
    - **analisis-forense/**: `volatility-memoria.md` (Adquisición RAM, netscan, malfind, procdump).
    - **incident-response/**: `metodologia-picerl.md` (Fases SANS, Contención vs Erradicación, SIEM/EDR).
    - **malware-analysis/**: `analisis-estatico-dinamico.md` (Hashing, Strings, PE analysis, YARA rules, Sandboxing).
- **Fase 09 - Sistema de Índices** — Implementación de navegación recursiva:
    - Creado `inventario/INDEX.md` maestro con enlaces a todas las fases.
    - Creados archivos `INDEX.md` en cada una de las 8 carpetas de fase y sus 20 subcarpetas de categoría.
    - Tablas de referencia rápida con MITRE IDs y dificultad en cada nivel de subcategoría.

### Actualizado
- **Estado del Proyecto**: Todas las fases del roadmap original han sido completadas con éxito.
- **TASKS.md**: Archivo eliminado tras la consecución de todos los objetivos.

---

## [2026-03-27] — Sesión 5

### Añadido
- **Fase 05 - Post-Explotación** — 20 técnicas nuevas:
    - **privilege-escalation/linux/** (7): `suid-sgid.md`, `abuso-sudo.md`, `abuso-cron-jobs.md`, `capabilities-linux.md`, `kernel-exploits-privesc-linux.md`, `nfs-no-root-squash.md`, `enumeracion-privesc-linux.md`
    - **privilege-escalation/windows/** (5): `token-impersonation.md`, `credential-dumping.md`, `abuso-servicios-windows.md`, `abuso-tareas-programadas.md`, `enumeracion-privesc-windows.md`
    - **persistencia/** (3): `persistencia-linux.md`, `persistencia-windows.md`, `web-shells.md`
    - **lateral-movement/** (3): `pass-the-hash.md`, `pivoting-tunneling.md`, `ejecucion-remota-windows.md`
    - **exfiltracion/** (2): `canales-encubiertos.md`, `transferencia-archivos.md`

### Corregido
- Edición incorrecta del libro de Allen en 7 archivos: corregido de "(4th ed.)" a "(2nd ed.)" según el PDF existente en `referencias/`
- Formato de entrada de herramientas LOLBAS en `enumeracion-privesc-linux.md`

### Actualizado
- Tabla de libros en `AGENTS.md` ordenada alfabéticamente por título

---

## [2026-03-24] — Sesión 4

### Añadido
- **Biblioteca de Referencias**: Incorporados 17 nuevos PDFs a la carpeta `referencias/` (total 33 libros), incluyendo *The Web Application Hacker's Handbook*, *Black Hat GraphQL* y *Wireshark 2 Cookbook*.
- **AGENTS.md**: Actualizada la tabla de fuentes de información para incluir los 33 libros categorizados por área técnica.

### Actualizado (Enriquecimiento Técnico)
- **Fase 03 - Análisis de Vulnerabilidades Web** (4 técnicas clave):
    - `analisis-xss.md`: Añadidos contextos de inyección (HTML, Atributos, JS), DOM-Based XSS y técnicas de evasión de filtros.
    - `analisis-ssrf.md`: Añadida exfiltración de metadatos de Cloud (AWS, GCP, DigitalOcean) y bypasses de filtros de IP/DNS.
    - `analisis-sql-injection.md`: Añadidas metodologías para Blind SQLi (Boolean/Time-based) y lectura de archivos con `load_file`.
    - `analisis-lfi-rfi.md`: Añadidos vectores avanzados con PHP Wrappers y técnica de RCE vía Log Poisoning.

### Corregido
- **Estandarización**: Restaurada la consistencia en los campos `Fase`, `Plataforma` y `Dificultad` en las técnicas web enriquecidas para mantener la compatibilidad con el sistema de índices.

---

## [2026-03-23] — Sesión 3

### Añadido
- **Fase 02 - Enumeración Servicios** (3 técnicas nuevas): `enumeracion-ldap.md`, `enumeracion-smtp.md`, `enumeracion-oracle.md`.
- **Fase 02 - Enumeración Servicios** (9 técnicas nuevas): `enumeracion-postgresql.md`, `enumeracion-redis.md`, `enumeracion-vnc.md`, `enumeracion-telnet.md`, `enumeracion-mongodb.md`, `enumeracion-docker.md`, `enumeracion-kubernetes.md`, `enumeracion-elasticsearch.md`, `enumeracion-memcached.md`, `enumeracion-rabbitmq.md`.
- **Fase 02 - Enumeración Red** (2 técnicas nuevas): `enumeracion-kerberos.md`, `enumeracion-ipmi.md`.
- **Fase 03 - Análisis de Vulnerabilidades Scanning** (2 técnicas): `analisis-nmap-nse.md`, `escaneo-openvas-gvm.md`.
- **Fase 03 - Análisis de Vulnerabilidades Web** (6 técnicas): `analisis-sql-injection.md`, `analisis-xss.md`, `analisis-csrf.md`, `analisis-idor.md`, `analisis-lfi-rfi.md`, `analisis-seguridad-cabeceras.md`.
- **Fase 03 - Análisis de Vulnerabilidades Sistema** (4 técnicas): `analisis-parches-windows.md`, `analisis-permisos-linux.md`, `analisis-servicios-mal-configurados.md`, `analisis-software-obsoleto.md`.
- **Fase 03 - Análisis de Vulnerabilidades Web** (8 técnicas adicionales): `analisis-cors.md`, `analisis-ssrf.md`, `analisis-ssti.md`, `analisis-command-injection.md`, `analisis-xxe.md`, `analisis-deserialization.md`, `analisis-open-redirect.md`, `analisis-nessus.md`.
- **Fase 04 - Explotación Web** (7 técnicas): `explotacion-sqli.md`, `explotacion-nosqli.md`, `explotacion-deserialization.md`, `explotacion-fileupload.md`, `explotacion-jwt.md`, `explotacion-auth-bypass-oauth.md`, `explotacion-cms-wordpress.md`.
- **Fase 04 - Explotación Red** (5 técnicas): `explotacion-arp-spoofing.md`, `explotacion-mitm-responder.md`, `explotacion-mitm6.md`, `explotacion-smb-relay.md`, `explotacion-adcs-relay.md`.
- **Fase 04 - Explotación Sistema** (6 técnicas): `explotacion-buffer-overflow-stack.md`, `explotacion-eternalblue.md`, `explotacion-shellshock.md`, `explotacion-zerologon.md`, `explotacion-kernel-linux.md`, `explotacion-kernel-windows.md`.
- **Fase 04 - Explotación Client-Side** (3 técnicas): `explotacion-msfvenom.md`, `explotacion-phishing-tecnico.md`, `explotacion-process-injection.md`.
- **Fase 04 - Explotación Credenciales** (3 técnicas): `explotacion-hash-cracking.md`, `explotacion-brute-force-advanced.md`, `explotacion-password-spraying.md`.
- **Template**: Creado `inventario/TEMPLATE.md` con estructura exacta, ejemplos de formato y notas para el redactor en comentario HTML.
- **Idioma y Ortografía**: Añadida sección en `AGENTS.md` requiriendo acentos y ortografía correcta en español.
- **Referencia al Template**: Actualizado `AGENTS.md` para apuntar a `inventario/TEMPLATE.md` como lectura obligatoria antes de crear archivos.

### Corregido (Fase 02 — post-review de 12 archivos nuevos)
- **MITRE ATT&CK IDs**: Corregidos 8 IDs incorrectos: redis/mongodb/elasticsearch/memcached T1595→T1046, telnet/ipmi/docker T1021.002→T1046, postgresql T1210→T1046. Añadidos T1558.003 y T1558.004 a kerberos.
- **Dificultad no estándar**: Corregidos 6 archivos: kerberos/ipmi/docker "Media"→"Intermedia", postgresql "Básica/Media"→"Intermedia", telnet "Muy Básica"→"Básica", kubernetes "Media/Alta"→"Avanzada".
- **Plataforma no estándar**: Corregidos 7 archivos que usaban listas o paréntesis ("Linux, Windows", "Hardware (...)") → "Multi".
- **Referencias faltantes**: Añadidas citas a libros de `referencias/` en los 12 archivos (Allen 2022, Harper et al. 2018).
- **VNC hashcat**: Corregido modo -m 3000 (LM hash) → uso de `vncpwd` para descifrado de contraseñas VNC.

### Corregido (Fase 03 — post-review de 12 archivos iniciales)
- **Campo Fase faltante**: Añadido `- **Fase**: Análisis de Vulnerabilidades` a los 12 archivos.
- **Orden de Clasificación**: Corregido de Dificultad→Plataforma→MITRE a Fase→MITRE→Plataforma→Dificultad en 12 archivos.
- **Formato de dos puntos**: Corregido `**Campo:**` → `**Campo**:` en 12 archivos.
- **Herramientas sin formato**: Añadido bold, módulos entre paréntesis y descripción con guión largo en 12 archivos.
- **MITRE ATT&CK IDs**: analisis-csrf T1595→T1185, analisis-idor T1595→T1213, analisis-seguridad-cabeceras T1595→T1595.002, analisis-servicios-mal-configurados T1068→T1078.
- **Autor incorrecto**: escaneo-openvas-gvm.md Velu V. (2017)→Allen M. (2022) para Mastering Kali Linux.

---

## [2026-03-23] — Sesión 2

### Añadido
- **Fase 02 - Enumeracion Web** (5 tecnicas): `fingerprinting-tecnologias-web.md`, `enumeracion-http-nmap.md`, `enumeracion-webdav.md`, `nikto.md`, `banner-grabbing-http.md`.
- **Fase 02 - Enumeracion Red** (4 tecnicas): `enumeracion-smb.md`, `enumeracion-snmp.md`, `enumeracion-nfs.md`, `enumeracion-dns.md`.
- **Fase 02 - Enumeracion Servicios** (6 tecnicas): `enumeracion-ssh.md`, `enumeracion-ftp.md`, `enumeracion-mysql.md`, `enumeracion-mssql.md`, `enumeracion-rdp.md`, `enumeracion-winrm.md`.
- **Fase 02 - Fuzzing** (4 tecnicas): `fuzzing-directorios-archivos.md`, `fuzzing-subdominios-vhosts.md`, `fuzzing-parametros.md`, `fuzzing-lfi-ssrf.md`.

### Corregido (Fase 02 — post-review)
- **MITRE IDs fuzzing**: `fuzzing-directorios-archivos.md` y `fuzzing-lfi-ssrf.md` T1083→T1595.002 (T1083 es post-compromiso local, no fuzzing HTTP externo).
- **MITRE IDs fuzzing**: `fuzzing-subdominios-vhosts.md` T1595.001→T1595.002 (T1595.001 modela IP block scanning, no subdomain enum).
- **MITRE IDs enumeracion**: `enumeracion-webdav.md` añadido T1190; `enumeracion-nfs.md` añadido T1548.001; `enumeracion-smb.md` expandido a T1087+T1069+T1007+T1110.
- **MITRE IDs servicios**: `enumeracion-ssh.md` y `enumeracion-ftp.md` corregidos — ID principal ahora T1046 (enumeracion), T1110.001 como secundario (fuerza bruta).
- **Herramienta deprecada**: `enumeracion-winrm.md` — reemplazado CrackMapExec (archivado 2024) por NetExec (`nxc`).
- **Referencias invalidas**: Reemplazado `Engebretson (2013)` en `nikto.md` y `enumeracion-ftp.md` (libro no disponible en `referencias/`) por `Gray Hat Hacking`.
- **Autoria incorrecta**: Corregido `Metasploit for Beginners` en `enumeracion-mysql.md` y `enumeracion-mssql.md` → autor correcto: Rahalkar, S. (2017).

---

## [2026-03-23] — Sesion 1

### Añadido
- **Fuentes de Internet**: Agregadas 30+ fuentes organizadas en 7 categorías al `AGENTS.md` (MITRE ATT&CK, OWASP, NVD, Exploit-DB, HackTricks, GTFOBins, LOLBAS, PTES, OSSTMM, NIST, etc.).
- **Fase 01 - Reconocimiento Pasivo** (8 técnicas): `google-dorking.md`, `shodan-censys.md`, `transparencia-certificados.md`, `dns-pasivo.md`, `fingerprinting-tecnologias-web.md`, `recoleccion-emails.md`, `wayback-machine.md`, `whois-registros-dominio.md`.
- **Fase 01 - Reconocimiento Activo** (6 técnicas): `descubrimiento-hosts.md`, `escaneo-puertos.md`, `fingerprinting-os-servicios.md`, `enumeracion-dns.md`, `escaneo-vulnerabilidades.md`, `deteccion-waf.md`.
- **Formato de Referencias APA**: Definida guía de formato APA 7ma edición en `AGENTS.md` con ejemplos para libros, frameworks online, herramientas/repos y notas del proyecto.

### Corregido
- **MITRE ATT&CK IDs**: Corregidos 4 IDs incorrectos (`deteccion-waf.md` T1595.001→T1595, `fingerprinting-tecnologias-web.md` T1592.004→T1592.002, `fingerprinting-os-servicios.md` T1592.001→T1592.002, `wayback-machine.md` T1593.002→T1593).
- **Clasificación**: Movido `deteccion-waf.md` de `pasivo/` a `activo/` (WAF detection requiere interacción con el target).
- **Info desactualizada**: Removida cookie `__cfduid` (deprecada por Cloudflare 2021), reemplazado `amap` (abandonado) por `nmap -sV --version-all`, corregida sintaxis de `retire.js`.
- **Comando redundante**: Corregido `-f --mtu 16` → `--mtu 16` en `descubrimiento-hosts.md`.
- **Warning faltante**: Agregada advertencia en `nmap --script exploit` (`escaneo-vulnerabilidades.md`).
- **Plataforma**: Corregido `dns-pasivo.md` de "Web" a "Multi".
- **Formato revisor**: Restaurado formato `**Herramientas**`/`**Instrucciones**` en `AGENTS.md`.

### Actualizado
- **Referencias a formato APA**: Las 14 técnicas de Fase 01 actualizadas a formato APA 7ma edición con datos reales de autores, editoriales y años.
- **Referencias a libros**: Incorporadas referencias a libros de `referencias/` en todas las técnicas (previamente solo referenciaban notas y MITRE).

## [2026-03-22]

### Añadido
- **Estructura del Inventario**: Creada la jerarquía de directorios completa (01-08) según la taxonomía definida en `AGENTS.md`.
- **Carpeta de Redundancia**: Creado el directorio `redundancia/` para almacenar versiones descartadas o duplicadas de notas de forma segura sin pérdida de información.
- **Herramienta de Diagnóstico**: Creado `compare_notes.py` para detectar inconsistencias entre `notas/` (HTML) y `notas-md/` (Markdown).
- **Heurísticas de Prioridad**: Actualizado `AGENTS.md` con reglas claras para la resolución de conflictos (Prioridad 1: Oficial, 2: Libros, 3: Notas personales).

### Analizado
- **Inconsistencias de Nombres**: Identificados archivos HTML con dobles espacios antes del hash, lo que causaba desajustes en la normalización.
- **Detección de Duplicados**: Identificada una nota redundante en `notas/` con dos versiones distintas (18K vs 19K): `DOM XSS in document write sink using source locati`.
