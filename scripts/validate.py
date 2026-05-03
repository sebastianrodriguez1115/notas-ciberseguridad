"""
Valida el frontmatter YAML de los archivos técnicos del inventario.

Uso:
    python scripts/validate.py
    python scripts/validate.py --quiet     # solo errores

Reglas:
1. Cada `.md` técnico (no INDEX.md ni TEMPLATE.md) debe empezar con `---\\n`.
2. Frontmatter parseable como YAML.
3. Campos requeridos: title, slug, aliases, fase, plataforma, dificultad,
   mitre. Opcionales: related, learning_refs.
4. Tipos correctos: arrays para fase/mitre/aliases/related/learning_refs;
   strings para title/slug/plataforma/dificultad.
5. Enums válidos: plataforma ∈ {Linux, Windows, Web, Red, Multi},
   dificultad ∈ {Básica, Intermedia, Avanzada}, fase ∈ las 7 fases.
6. Slugs únicos globalmente.
7. slug == nombre del archivo sin extensión (kebab-case derivado).
8. title del frontmatter coincide con el primer H1 del body.
9. mitre con formato T\\d{4}(\\.\\d{3})?. Permitido vacío sólo si fase
   incluye Fundamentos o Forense y DFIR.
10. related: cada slug existe en otro archivo del inventario.
11. learning_refs: cada path apunta a un directorio que existe en learning/
    y contiene `writeup.md` (estricto, ver "Política learning_refs" en AGENTS.md).
12. Body NO contiene `## Clasificación`.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("error: PyYAML no instalado. pip install pyyaml", file=sys.stderr)
    sys.exit(2)

REPO_ROOT = Path(__file__).resolve().parent.parent
INVENTORY = REPO_ROOT / "inventario"
LEARNING = REPO_ROOT / "learning"

PLATAFORMA_VALID = {"Linux", "Windows", "Web", "Red", "Multi"}
DIFICULTAD_VALID = {"Básica", "Intermedia", "Avanzada"}
FASE_VALID = {
    "Reconocimiento",
    "Enumeración",
    "Análisis de Vulnerabilidades",
    "Explotación",
    "Post-Explotación",
    "Fundamentos",
    "Forense y DFIR",
}
REQUIRED = ["title", "slug", "aliases", "fase", "plataforma", "dificultad", "mitre"]
OPTIONAL = ["related", "learning_refs"]
MITRE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
SLUG_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n(.*)", re.DOTALL)
H1_RE = re.compile(r"^# (.+)$", re.MULTILINE)


def parse_frontmatter(path: Path) -> tuple[dict | None, str | None, list[str]]:
    """Devuelve (parsed_yaml, body, errors)."""
    errors: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except Exception as e:
        return None, None, [f"cannot read: {e}"]

    m = FRONTMATTER_RE.match(text)
    if not m:
        return None, text, ["no frontmatter (file does not start with --- block)"]

    raw_yaml = m.group(1)
    body = m.group(2)
    try:
        parsed = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as e:
        return None, body, [f"YAML parse error: {e}"]
    if not isinstance(parsed, dict):
        return None, body, ["frontmatter is not a mapping"]
    return parsed, body, errors


def validate_file(path: Path, all_slugs: dict[str, Path]) -> list[str]:
    fm, body, errors = parse_frontmatter(path)
    if fm is None:
        return errors

    # Required fields
    for field in REQUIRED:
        if field not in fm:
            errors.append(f"missing required field: {field}")

    # Slug: tipo, formato kebab-case, igual a filename, único globalmente
    slug = fm.get("slug")
    if slug is not None:
        if not isinstance(slug, str):
            errors.append(f"slug must be string, got {type(slug).__name__}")
        else:
            if not SLUG_RE.match(slug):
                errors.append(
                    f"slug {slug!r} not in kebab-case (regex: {SLUG_RE.pattern})"
                )
            if slug != path.stem:
                errors.append(
                    f"slug {slug!r} must equal filename without extension "
                    f"({path.stem!r}); ver convención de naming en AGENTS.md"
                )
            if slug in all_slugs and all_slugs[slug] != path:
                errors.append(
                    f"duplicate slug {slug!r} (also in {all_slugs[slug].relative_to(REPO_ROOT)})"
                )
            all_slugs[slug] = path

    # title vs H1 (defensive: title puede no ser string si el YAML está mal)
    title = fm.get("title")
    if title is not None:
        if not isinstance(title, str):
            errors.append(f"title must be string, got {type(title).__name__}")
        elif body:
            h1 = H1_RE.search(body)
            if h1:
                if h1.group(1).strip() != title.strip():
                    errors.append(
                        f"title mismatch: frontmatter={title!r} vs H1={h1.group(1)!r}"
                    )
            else:
                errors.append("body has no H1")

    # Enums (defensive: rechazar tipos no-string para evitar TypeError en `in`)
    plat = fm.get("plataforma")
    if plat is not None:
        if not isinstance(plat, str):
            errors.append(f"plataforma must be string, got {type(plat).__name__}")
        elif plat not in PLATAFORMA_VALID:
            errors.append(f"invalid plataforma: {plat!r}")
    dif = fm.get("dificultad")
    if dif is not None:
        if not isinstance(dif, str):
            errors.append(f"dificultad must be string, got {type(dif).__name__}")
        elif dif not in DIFICULTAD_VALID:
            errors.append(f"invalid dificultad: {dif!r}")

    # Arrays
    fase = fm.get("fase")
    if fase is not None:
        if not isinstance(fase, list):
            errors.append("fase must be array")
        else:
            for f in fase:
                if not isinstance(f, str):
                    errors.append(f"fase item must be string, got {type(f).__name__}: {f!r}")
                elif f not in FASE_VALID:
                    errors.append(f"invalid fase value: {f!r}")

    aliases = fm.get("aliases")
    if aliases is not None:
        if not isinstance(aliases, list):
            errors.append("aliases must be array")
        else:
            for a in aliases:
                if not isinstance(a, str):
                    errors.append(f"aliases item must be string, got {type(a).__name__}: {a!r}")

    mitre = fm.get("mitre")
    if mitre is not None:
        if not isinstance(mitre, list):
            errors.append("mitre must be array")
        else:
            for mid in mitre:
                if not isinstance(mid, str) or not MITRE_RE.match(mid):
                    errors.append(f"invalid mitre ID: {mid!r}")
            # Empty mitre only allowed for conceptual content
            if not mitre:
                fase_list = fase if isinstance(fase, list) else []
                fase_set = {f for f in fase_list if isinstance(f, str)}
                if not (fase_set & {"Fundamentos", "Forense y DFIR"}):
                    errors.append(
                        "empty mitre array: only allowed for Fundamentos or Forense y DFIR"
                    )

    # related & learning_refs: tipo array + items strings (validador cruzado en cross_validate)
    for opt in OPTIONAL:
        val = fm.get(opt)
        if val is None:
            continue
        if not isinstance(val, list):
            errors.append(f"{opt} must be array")
            continue
        for item in val:
            if not isinstance(item, str):
                errors.append(
                    f"{opt} item must be string, got {type(item).__name__}: {item!r}"
                )

    # No `## Clasificación` in body
    if body and re.search(r"^## Clasificación\b", body, re.MULTILINE):
        errors.append("body still has `## Clasificación` (deprecated)")

    return errors


def cross_validate(
    files_data: dict[Path, dict], all_slugs: dict[str, Path]
) -> dict[Path, list[str]]:
    """Valida `related` y `learning_refs` después de tener todos los slugs.

    Pre-condición: validate_file ya validó tipos. Aquí asumimos strings, pero
    seguimos siendo defensivos: items no-string se saltan (ya reportados arriba).
    """
    cross_errors: dict[Path, list[str]] = {}
    for path, fm in files_data.items():
        errs = []
        for slug in fm.get("related", []) or []:
            if not isinstance(slug, str):
                continue  # type error ya reportado en validate_file
            if slug not in all_slugs:
                errs.append(f"related slug {slug!r} does not exist")
        for ref in fm.get("learning_refs", []) or []:
            if not isinstance(ref, str):
                continue
            ref_path = LEARNING / ref
            if not ref_path.is_dir():
                errs.append(f"learning_refs path does not exist: {ref}")
            elif not (ref_path / "writeup.md").is_file():
                errs.append(
                    f"learning_refs path missing writeup.md: {ref} "
                    "(política: cada writeup linkeable debe consolidarse en writeup.md)"
                )
        if errs:
            cross_errors[path] = errs
    return cross_errors


def collect_files() -> list[Path]:
    files = sorted(INVENTORY.rglob("*.md"))
    meta_dir = INVENTORY / "meta"
    return [
        f
        for f in files
        if f.name not in {"INDEX.md", "TEMPLATE.md", "TOPICS.md"}
        and meta_dir not in f.parents
    ]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--quiet", action="store_true", help="solo mostrar errores")
    args = p.parse_args()

    files = collect_files()
    all_slugs: dict[str, Path] = {}
    files_data: dict[Path, dict] = {}
    per_file_errors: dict[Path, list[str]] = {}

    for f in files:
        try:
            errors = validate_file(f, all_slugs)
        except Exception as e:
            # Red de seguridad: si un edge case escapa los type checks,
            # reportar el archivo como errored y continuar con el resto.
            errors = [f"unexpected validator error: {type(e).__name__}: {e}"]
        try:
            fm, _, _ = parse_frontmatter(f)
            if fm:
                files_data[f] = fm
        except Exception as e:
            errors.append(f"unexpected parse error: {type(e).__name__}: {e}")
        if errors:
            per_file_errors[f] = errors

    cross_failed = False
    try:
        cross = cross_validate(files_data, all_slugs)
    except Exception as e:
        print(f"FATAL cross-validation crashed: {type(e).__name__}: {e}", file=sys.stderr)
        cross = {}
        cross_failed = True
    for path, errs in cross.items():
        per_file_errors.setdefault(path, []).extend(errs)

    n_total = len(files)
    n_with_errors = len(per_file_errors)
    n_ok = n_total - n_with_errors

    if not args.quiet:
        print(f"Validating {n_total} files...")
    for path in sorted(per_file_errors):
        rel = path.relative_to(REPO_ROOT)
        for err in per_file_errors[path]:
            print(f"ERR {rel}: {err}")

    print()
    if cross_failed:
        print(
            "summary: cross-validation crashed (see FATAL above); marcando como failure"
        )
        sys.exit(1)
    print(f"summary: {n_ok}/{n_total} OK, {n_with_errors} files with errors")
    sys.exit(1 if n_with_errors else 0)


if __name__ == "__main__":
    main()
