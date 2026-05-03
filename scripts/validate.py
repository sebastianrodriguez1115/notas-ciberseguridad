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
7. title del frontmatter coincide con el primer H1 del body.
8. mitre con formato T\\d{4}(\\.\\d{3})?. Permitido vacío sólo si fase
   incluye Fundamentos o Forense y DFIR.
9. related: cada slug existe en otro archivo del inventario.
10. learning_refs: cada path apunta a un directorio que existe en learning/
    y contiene un writeup.md o algún .md.
11. Body NO contiene `## Clasificación`.
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

    # Slug uniqueness check (deferred to caller via all_slugs)
    slug = fm.get("slug")
    if slug:
        if not isinstance(slug, str):
            errors.append(f"slug must be string, got {type(slug).__name__}")
        else:
            if slug in all_slugs and all_slugs[slug] != path:
                errors.append(
                    f"duplicate slug {slug!r} (also in {all_slugs[slug].relative_to(REPO_ROOT)})"
                )
            all_slugs[slug] = path

    # title vs H1
    title = fm.get("title")
    if title and body:
        h1 = H1_RE.search(body)
        if h1:
            if h1.group(1).strip() != title.strip():
                # Tolerar discrepancia menor: a veces el title es la versión
                # corta y el H1 incluye paréntesis con info adicional. Avisar
                # como warning suave (todavía error pero descriptible).
                errors.append(
                    f"title mismatch: frontmatter={title!r} vs H1={h1.group(1)!r}"
                )
        else:
            errors.append("body has no H1")

    # Enums
    plat = fm.get("plataforma")
    if plat is not None and plat not in PLATAFORMA_VALID:
        errors.append(f"invalid plataforma: {plat!r}")
    dif = fm.get("dificultad")
    if dif is not None and dif not in DIFICULTAD_VALID:
        errors.append(f"invalid dificultad: {dif!r}")

    # Arrays
    fase = fm.get("fase")
    if fase is not None:
        if not isinstance(fase, list):
            errors.append("fase must be array")
        else:
            for f in fase:
                if f not in FASE_VALID:
                    errors.append(f"invalid fase value: {f!r}")

    aliases = fm.get("aliases")
    if aliases is not None and not isinstance(aliases, list):
        errors.append("aliases must be array")

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
                fase_set = set(fase or [])
                if not (fase_set & {"Fundamentos", "Forense y DFIR"}):
                    errors.append(
                        "empty mitre array: only allowed for Fundamentos or Forense y DFIR"
                    )

    # related & learning_refs (validated later for resolution)
    for opt in OPTIONAL:
        if opt in fm and not isinstance(fm[opt], list):
            errors.append(f"{opt} must be array")

    # No `## Clasificación` in body
    if body and re.search(r"^## Clasificación\b", body, re.MULTILINE):
        errors.append("body still has `## Clasificación` (deprecated)")

    return errors


def cross_validate(
    files_data: dict[Path, dict], all_slugs: dict[str, Path]
) -> dict[Path, list[str]]:
    """Valida `related` y `learning_refs` después de tener todos los slugs."""
    cross_errors: dict[Path, list[str]] = {}
    for path, fm in files_data.items():
        errs = []
        for slug in fm.get("related", []) or []:
            if slug not in all_slugs:
                errs.append(f"related slug {slug!r} does not exist")
        for ref in fm.get("learning_refs", []) or []:
            ref_path = LEARNING / ref
            if not ref_path.is_dir():
                errs.append(f"learning_refs path does not exist: {ref}")
            else:
                mds = list(ref_path.glob("*.md"))
                if not mds:
                    errs.append(f"learning_refs path has no .md files: {ref}")
        if errs:
            cross_errors[path] = errs
    return cross_errors


def collect_files() -> list[Path]:
    files = sorted(INVENTORY.rglob("*.md"))
    return [f for f in files if f.name not in {"INDEX.md", "TEMPLATE.md"}]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--quiet", action="store_true", help="solo mostrar errores")
    args = p.parse_args()

    files = collect_files()
    all_slugs: dict[str, Path] = {}
    files_data: dict[Path, dict] = {}
    per_file_errors: dict[Path, list[str]] = {}

    for f in files:
        errors = validate_file(f, all_slugs)
        fm, _, _ = parse_frontmatter(f)
        if fm:
            files_data[f] = fm
        if errors:
            per_file_errors[f] = errors

    cross = cross_validate(files_data, all_slugs)
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
    print(f"summary: {n_ok}/{n_total} OK, {n_with_errors} files with errors")
    sys.exit(1 if n_with_errors else 0)


if __name__ == "__main__":
    main()
