"""
One-shot migration: convierte la sección `## Clasificación` de cada archivo
técnico del inventario en frontmatter YAML al inicio.

Uso:
    python scripts/migrate_frontmatter.py inventario/02-enumeracion
    python scripts/migrate_frontmatter.py inventario/02-enumeracion --dry-run

- Salta archivos que ya tienen frontmatter (`---` en línea 1).
- Salta INDEX.md y TEMPLATE.md.
- Extrae title (del H1), fase (split coma+espacio), plataforma, dificultad,
  mitre (regex sobre todo el bloque MITRE para soportar multi-IDs), y deriva
  slug del nombre de archivo (sin extensión, sin prefijos de acción).
- aliases default a [title]; related y learning_refs default a [].
- Quita el bloque `## Clasificación` (incluye 4 bullets + blank line).
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

MITRE_RE = re.compile(r"\bT(\d{4})(?:\.(\d{3}))?\b")
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


def derive_slug(path: Path) -> str:
    """Slug = filename sin extensión. Naming convention ya da kebab-case."""
    return path.stem


def extract_h1(text: str) -> str | None:
    m = re.search(r"^# (.+)$", text, re.MULTILINE)
    return m.group(1).strip() if m else None


def extract_clasificacion_block(text: str) -> tuple[str, dict] | None:
    """Devuelve (block_text, parsed_dict) o None si no existe."""
    # Match Clasificación section: from `## Clasificación` to next `## ` (any section)
    m = re.search(
        r"## Clasificación\n(.*?)(?=\n## [A-Z])",
        text,
        re.DOTALL,
    )
    if not m:
        return None
    block = m.group(0)
    inner = m.group(1)

    parsed: dict = {}

    # Fase
    fase_m = re.search(r"\*\*Fase\*\*:\s*(.+)", inner)
    if fase_m:
        parsed["fase"] = [v.strip() for v in fase_m.group(1).split(",")]

    # MITRE: capturar todos los T-IDs en cualquier subline del bloque MITRE
    # El bloque MITRE puede ser de una línea o multilínea. Buscar desde
    # "**MITRE ATT&CK**:" hasta el siguiente bullet `- **` o final del inner.
    mitre_m = re.search(
        r"\*\*MITRE ATT&CK\*\*:\s*(.+?)(?=\n- \*\*|\Z)",
        inner,
        re.DOTALL,
    )
    if mitre_m:
        # Stripear URLs de markdown links para evitar capturar T-IDs internos
        # de paths como `attack.mitre.org/techniques/T1592/002/`. Reemplazamos
        # `[texto](url)` por sólo `texto`, así el T-ID legítimo del texto se
        # captura pero los del URL no.
        mitre_text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", mitre_m.group(1))
        ids = []
        seen = set()
        for tm in MITRE_RE.finditer(mitre_text):
            base, sub = tm.group(1), tm.group(2)
            t_id = f"T{base}" + (f".{sub}" if sub else "")
            if t_id not in seen:
                seen.add(t_id)
                ids.append(t_id)
        parsed["mitre"] = ids

    # Plataforma
    plat_m = re.search(r"\*\*Plataforma\*\*:\s*(\S+)", inner)
    if plat_m:
        parsed["plataforma"] = plat_m.group(1).strip()

    # Dificultad
    dif_m = re.search(r"\*\*Dificultad\*\*:\s*(\S+)", inner)
    if dif_m:
        parsed["dificultad"] = dif_m.group(1).strip()

    return block, parsed


# Scalars que YAML 1.1 (PyYAML safe_load default) resuelve a bool/null/Y/N.
# Todas las case-variantes (TRUE, true, True) caen aquí.
_YAML_RESERVED_SCALARS = re.compile(
    r"^(true|false|yes|no|on|off|y|n|null|None|~)$",
    re.IGNORECASE,
)
# Números enteros, flotantes, notación científica.
_YAML_NUMBER = re.compile(r"^[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?$")
# Otras bases reconocidas: 0x, 0o, 0b, octal con prefijo 0.
_YAML_NUMBER_RADIX = re.compile(r"^[+-]?0([xX][0-9a-fA-F]+|[oO][0-7]+|[bB][01]+|[0-7]+)$")
# Caracteres que requieren quoting en flow-context (donde emitimos arrays inline).
# Incluye los que YAML interpreta especiales en cualquier lado más los de flow.
_YAML_FLOW_SPECIAL = set(":#&*!|>%@`'\"" + ",[]{}")
# Si el primer char es uno de estos, también requiere quoting (puede iniciar
# sintaxis YAML: anchor, alias, tag, list item, mapping, etc.).
_YAML_RESERVED_PREFIXES = ("-", "?", ":", " ", "\t")


def _needs_quoting(s: str) -> bool:
    """¿Hay que quotar este scalar para garantizar que PyYAML lo lea como string?"""
    if s == "":
        return True
    if _YAML_RESERVED_SCALARS.match(s):
        return True
    if _YAML_NUMBER.match(s) or _YAML_NUMBER_RADIX.match(s):
        return True
    if any(c in s for c in _YAML_FLOW_SPECIAL):
        return True
    if s.startswith(_YAML_RESERVED_PREFIXES):
        return True
    if s.endswith((" ", "\t")):
        return True
    return False


def yaml_scalar(s: str) -> str:
    """Emite un string como scalar YAML. Quota cuando es necesario para que
    PyYAML safe_load lo reconstruya como string y no como bool/null/number.
    Escapa `\\` y `"` internas cuando quota."""
    if not isinstance(s, str):
        raise TypeError(f"yaml_scalar expects str, got {type(s).__name__}")
    if not _needs_quoting(s):
        return s
    escaped = s.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def yaml_array(values: list[str]) -> str:
    """Render una lista como YAML array inline. Cada item pasa por yaml_scalar
    para que strings ambiguos (No, true, 123, etc.) se quoten correctamente."""
    return "[" + ", ".join(yaml_scalar(v) for v in values) + "]"


def build_frontmatter(title: str, slug: str, parsed: dict) -> str:
    fase = parsed.get("fase", [])
    plataforma = parsed.get("plataforma", "")
    dificultad = parsed.get("dificultad", "")
    mitre = parsed.get("mitre", [])
    aliases = [title]

    return (
        "---\n"
        f"title: {yaml_scalar(title)}\n"
        f"slug: {slug}\n"
        f"aliases: {yaml_array(aliases)}\n"
        f"fase: {yaml_array(fase)}\n"
        f"plataforma: {plataforma}\n"
        f"dificultad: {dificultad}\n"
        f"mitre: {yaml_array(mitre)}\n"
        f"related: []\n"
        f"learning_refs: []\n"
        "---\n"
    )


def validate(parsed: dict, path: Path) -> list[str]:
    errors = []
    fase = parsed.get("fase", [])
    if not fase:
        errors.append("missing fase")
    for f in fase:
        if f not in FASE_VALID:
            errors.append(f"invalid fase: {f!r}")
    if parsed.get("plataforma") not in PLATAFORMA_VALID:
        errors.append(f"invalid plataforma: {parsed.get('plataforma')!r}")
    if parsed.get("dificultad") not in DIFICULTAD_VALID:
        errors.append(f"invalid dificultad: {parsed.get('dificultad')!r}")
    # mitre es opcional para contenido conceptual (Fundamentos, Forense y DFIR
    # metodológico). Si Fase incluye "Fundamentos" o "Forense y DFIR" y no hay
    # mitre, se acepta como [].
    fase_set = set(fase)
    conceptual = bool(fase_set & {"Fundamentos", "Forense y DFIR"})
    if not parsed.get("mitre") and not conceptual:
        errors.append("missing mitre IDs")
    return errors


def migrate_file(path: Path, dry_run: bool) -> tuple[bool, str]:
    text = path.read_text(encoding="utf-8")

    if text.startswith("---\n"):
        return False, "skip (already has frontmatter)"

    title = extract_h1(text)
    if not title:
        return False, "skip (no H1 found)"

    result = extract_clasificacion_block(text)
    if not result:
        return False, "skip (no Clasificación block)"
    block, parsed = result

    errors = validate(parsed, path)
    if errors:
        return False, "errors: " + "; ".join(errors)

    slug = derive_slug(path)
    frontmatter = build_frontmatter(title, slug, parsed)

    # Remove Clasificación block + its trailing blank line(s) before next section
    # block ends right before `\n## NextSection`; we want to also remove the
    # blank line(s) between block and next section.
    new_text = text.replace(block + "\n", "", 1)

    # Prepend frontmatter
    new_text = frontmatter + "\n" + new_text

    if dry_run:
        return True, "OK (dry-run)"

    path.write_text(new_text, encoding="utf-8")
    return True, "OK"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("root", help="Directorio a migrar (ej. inventario/02-enumeracion)")
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args()

    root = Path(args.root)
    if not root.is_dir():
        print(f"error: {root} no es directorio", file=sys.stderr)
        sys.exit(1)

    files = sorted(root.rglob("*.md"))
    files = [f for f in files if f.name not in {"INDEX.md", "TEMPLATE.md"}]

    n_ok, n_skip, n_err = 0, 0, 0
    for f in files:
        changed, msg = migrate_file(f, args.dry_run)
        prefix = "OK " if changed else ("ERR" if msg.startswith("errors") else "---")
        if changed:
            n_ok += 1
        elif msg.startswith("errors"):
            n_err += 1
        else:
            n_skip += 1
        print(f"{prefix} {f}: {msg}")

    print()
    print(f"summary: {n_ok} migrated, {n_skip} skipped, {n_err} errors")
    sys.exit(1 if n_err else 0)


if __name__ == "__main__":
    main()
