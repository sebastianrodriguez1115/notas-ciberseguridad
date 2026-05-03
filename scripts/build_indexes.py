"""
Regenera los INDEX.md hoja del inventario y construye índices facetados
en `inventario/meta/` y un `inventario/TOPICS.md` global, todos derivados
del frontmatter de los archivos técnicos.

Uso:
    python scripts/build_indexes.py
    python scripts/build_indexes.py --check    # falla si hay diff (CI)

Lo que toca:
- `inventario/0X-fase/<subcat>/INDEX.md`: regenera la tabla
  `Técnica | MITRE | Dificultad | Plataforma`. Preserva H1 y descripción
  (todo lo que esté ANTES del primer marcador de tabla `| :---`).
- `inventario/TOPICS.md`: nuevo, índice plano por slug con title, path,
  related y learning_refs.
- `inventario/meta/by-mitre.md`, `by-difficulty.md`, `by-platform.md`,
  `by-fase.md`: vistas facetadas auto-generadas.

NO toca:
- `inventario/INDEX.md` (master, narrativo).
- `inventario/0X-fase/INDEX.md` (de fase, narrativo).
- Los archivos técnicos.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    print("error: PyYAML no instalado. pip install pyyaml", file=sys.stderr)
    sys.exit(2)

REPO_ROOT = Path(__file__).resolve().parent.parent
INVENTORY = REPO_ROOT / "inventario"
META_DIR = INVENTORY / "meta"
FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n(.*)", re.DOTALL)
TABLE_HEADER_RE = re.compile(r"^\| :---", re.MULTILINE)
AUTOGEN_NOTICE = (
    "<!-- AUTOGENERADO por scripts/build_indexes.py. NO editar a mano la tabla. -->"
)
# Display name de cada fase para el backlink. Mapping de dir name → display.
PHASE_DISPLAY = {
    "01-reconocimiento": "Reconocimiento",
    "02-enumeracion": "Enumeración",
    "03-analisis-vulnerabilidades": "Análisis de Vulnerabilidades",
    "04-explotacion": "Explotación",
    "05-post-explotacion": "Post-Explotación",
    "06-frameworks-herramientas": "Frameworks y Herramientas",
    "07-fundamentos": "Fundamentos",
    "08-forense-dfir": "Forense y DFIR",
}


def parse_frontmatter(path: Path) -> dict | None:
    text = path.read_text(encoding="utf-8")
    m = FRONTMATTER_RE.match(text)
    if not m:
        return None
    try:
        return yaml.safe_load(m.group(1))
    except yaml.YAMLError:
        return None


def short_title(title: str) -> str:
    """Si el title tiene `<prefijo>: <real>`, devolver `<real>`. Si no, title."""
    if ":" in title:
        return title.split(":", 1)[1].strip()
    return title


def collect_files() -> list[tuple[Path, dict]]:
    out = []
    for f in sorted(INVENTORY.rglob("*.md")):
        if f.name in {"INDEX.md", "TEMPLATE.md"}:
            continue
        if f.is_relative_to(META_DIR):
            continue
        fm = parse_frontmatter(f)
        if fm:
            out.append((f, fm))
    return out


def render_table(rows: list[tuple[str, str, str, str, str]]) -> str:
    """rows: [(display_title, link_relative, mitre, dificultad, plataforma), ...]"""
    lines = [
        "| Técnica | MITRE | Dificultad | Plataforma |",
        "| :--- | :--- | :--- | :--- |",
    ]
    for title, link, mitre, dif, plat in rows:
        lines.append(f"| [{title}]({link}) | {mitre} | {dif} | {plat} |")
    return "\n".join(lines)


def regen_leaf_index(leaf_dir: Path, files: list[tuple[Path, dict]]) -> str | None:
    """Regenera el INDEX.md hoja en leaf_dir. Preserva H1 + descripción + backlink."""
    index_path = leaf_dir / "INDEX.md"
    if not index_path.exists():
        return None

    sibling_files = [
        (f, fm)
        for f, fm in files
        if f.parent == leaf_dir
    ]
    if not sibling_files:
        return None

    rows = []
    for f, fm in sibling_files:
        title = fm.get("title", f.stem)
        display = short_title(title)
        link = f"./{f.name}"
        mitre_list = fm.get("mitre", []) or []
        mitre = mitre_list[0] if mitre_list else "—"
        dif = fm.get("dificultad", "—")
        plat = fm.get("plataforma", "—")
        rows.append((display, link, mitre, dif, plat))
    rows.sort(key=lambda r: r[0].lower())
    table = render_table(rows)

    existing = index_path.read_text(encoding="utf-8")

    # Narrativa: todo lo que haya ANTES del primer marcador AUTOGEN o, si no
    # existe, antes del primer `|` de tabla. Esto garantiza idempotencia
    # (regenerar dos veces produce el mismo output).
    autogen_pos = existing.find(AUTOGEN_NOTICE)
    if autogen_pos != -1:
        narrative_raw = existing[:autogen_pos]
    else:
        table_start = existing.find("|")
        narrative_raw = existing[:table_start] if table_start != -1 else existing
    narrative = narrative_raw.rstrip() + "\n\n"

    # Determinar backlink (al INDEX de la fase padre). Para subdirectorios anidados
    # como privilege-escalation/linux/, subir hasta encontrar el directorio de fase.
    phase_dir = leaf_dir
    while phase_dir.parent != INVENTORY and phase_dir.parent != REPO_ROOT:
        phase_dir = phase_dir.parent
    phase_display = PHASE_DISPLAY.get(phase_dir.name, phase_dir.name)
    rel_to_phase = "/".join([".."] * (len(leaf_dir.relative_to(phase_dir).parts))) + "/INDEX.md"
    backlink_text = f"[Volver a {phase_display}]({rel_to_phase})"

    new_content = (
        narrative
        + AUTOGEN_NOTICE
        + "\n\n"
        + table
        + "\n\n---\n"
        + backlink_text
        + "\n"
    )
    return new_content


def build_topics(files: list[tuple[Path, dict]]) -> str:
    lines = [
        "# TOPICS.md — Índice por slug",
        "",
        AUTOGEN_NOTICE,
        "",
        "Cada entrada lista el slug, el archivo del inventario, alias declarados,",
        "slugs relacionados y writeups en `learning/`. Generado desde frontmatter.",
        "",
    ]

    by_slug: dict[str, tuple[Path, dict]] = {}
    for f, fm in files:
        slug = fm.get("slug")
        if slug:
            by_slug[slug] = (f, fm)

    for slug in sorted(by_slug):
        f, fm = by_slug[slug]
        rel = f.relative_to(INVENTORY)
        title = fm.get("title", slug)
        aliases = fm.get("aliases", []) or []
        related = fm.get("related", []) or []
        learning_refs = fm.get("learning_refs", []) or []
        fase = ", ".join(fm.get("fase", []) or [])
        plat = fm.get("plataforma", "—")
        dif = fm.get("dificultad", "—")

        lines.append(f"## `{slug}` — {title}")
        lines.append("")
        lines.append(f"- **Archivo**: [`inventario/{rel}`](./{rel})")
        lines.append(f"- **Fase**: {fase} · **Plataforma**: {plat} · **Dificultad**: {dif}")
        if aliases:
            lines.append(f"- **Aliases**: {', '.join(aliases)}")
        if related:
            lines.append(f"- **Related**: {', '.join(f'`{r}`' for r in related)}")
        if learning_refs:
            lines.append(
                "- **Learning**: "
                + ", ".join(f"[`{r}`](../learning/{r}/)" for r in learning_refs)
            )
        lines.append("")

    return "\n".join(lines)


def build_facet_index(
    files: list[tuple[Path, dict]],
    facet: str,
    title: str,
    extractor,
) -> str:
    """Construye un índice facetado. extractor recibe fm y devuelve list[str]."""
    grouped: dict[str, list[tuple[Path, dict]]] = defaultdict(list)
    for f, fm in files:
        for value in extractor(fm):
            grouped[value].append((f, fm))

    lines = [
        f"# {title}",
        "",
        AUTOGEN_NOTICE,
        "",
        "Índice facetado generado desde frontmatter. Cada sección agrupa los",
        f"archivos por valor de `{facet}`.",
        "",
    ]

    for key in sorted(grouped):
        lines.append(f"## {key} ({len(grouped[key])})")
        lines.append("")
        for f, fm in sorted(grouped[key], key=lambda x: x[1].get("slug", "")):
            slug = fm.get("slug", f.stem)
            title_short = short_title(fm.get("title", slug))
            rel = f.relative_to(INVENTORY)
            lines.append(f"- [`{slug}`](../{rel}) — {title_short}")
        lines.append("")

    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--check", action="store_true", help="falla si hay diff")
    args = p.parse_args()

    files = collect_files()
    if not files:
        print("error: no se encontraron archivos con frontmatter", file=sys.stderr)
        sys.exit(2)

    diffs: list[Path] = []

    # 1. Regenerar leaf INDEX.md
    leaf_dirs: set[Path] = {f.parent for f, _ in files}
    for leaf_dir in sorted(leaf_dirs):
        new = regen_leaf_index(leaf_dir, files)
        if new is None:
            continue
        index_path = leaf_dir / "INDEX.md"
        old = index_path.read_text(encoding="utf-8") if index_path.exists() else ""
        if old != new:
            diffs.append(index_path)
            if not args.check:
                index_path.write_text(new, encoding="utf-8")

    # 2. TOPICS.md
    topics = build_topics(files)
    topics_path = INVENTORY / "TOPICS.md"
    if not topics_path.exists() or topics_path.read_text(encoding="utf-8") != topics:
        diffs.append(topics_path)
        if not args.check:
            topics_path.write_text(topics, encoding="utf-8")

    # 3. meta/ facets. mkdir solo cuando vamos a escribir (en --check no
    # tocamos filesystem aunque el directorio falte).
    if not args.check:
        META_DIR.mkdir(exist_ok=True)
    facet_specs = [
        ("by-mitre.md", "by-mitre", "Inventario por MITRE ATT&CK", lambda fm: fm.get("mitre", []) or ["(sin MITRE)"]),
        ("by-difficulty.md", "by-difficulty", "Inventario por Dificultad", lambda fm: [fm.get("dificultad", "—")]),
        ("by-platform.md", "by-platform", "Inventario por Plataforma", lambda fm: [fm.get("plataforma", "—")]),
        ("by-fase.md", "by-fase", "Inventario por Fase", lambda fm: fm.get("fase", []) or ["—"]),
    ]
    for filename, facet, title, extractor in facet_specs:
        content = build_facet_index(files, facet, title, extractor)
        fpath = META_DIR / filename
        if not fpath.exists() or fpath.read_text(encoding="utf-8") != content:
            diffs.append(fpath)
            if not args.check:
                fpath.write_text(content, encoding="utf-8")

    if args.check:
        if diffs:
            print(f"out of date: {len(diffs)} files would change")
            for d in diffs:
                print(f"  {d.relative_to(REPO_ROOT)}")
            sys.exit(1)
        print("up to date")
        sys.exit(0)

    print(f"regenerated {len(diffs)} files")
    for d in diffs:
        print(f"  {d.relative_to(REPO_ROOT)}")


if __name__ == "__main__":
    main()
