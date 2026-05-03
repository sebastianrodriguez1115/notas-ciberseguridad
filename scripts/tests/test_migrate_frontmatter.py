"""Tests para scripts/migrate_frontmatter.py."""
from __future__ import annotations

from pathlib import Path

import pytest

import migrate_frontmatter as mf


# ---------- helpers ----------


def make_legacy_md(path: Path, *, title: str, fase: str, mitre_block: str, plat: str, dif: str, body_extra: str = "") -> Path:
    """Genera un .md con sección ## Clasificación (formato legacy pre-frontmatter)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    content = f"""# {title}

## Descripción
Texto descriptivo.

## Clasificación
- **Fase**: {fase}
- **MITRE ATT&CK**: {mitre_block}
- **Plataforma**: {plat}
- **Dificultad**: {dif}

## Herramientas
- Tool — uso

## Referencias
- Foo
{body_extra}"""
    path.write_text(content, encoding="utf-8")
    return path


# ---------- yaml_scalar / yaml_array ----------


def test_yaml_scalar_quotes_when_special_char():
    assert mf.yaml_scalar("Hello: World") == '"Hello: World"'
    assert mf.yaml_scalar("foo & bar") == '"foo & bar"'
    assert mf.yaml_scalar("plain") == "plain"


def test_yaml_scalar_escapes_internal_quotes():
    assert mf.yaml_scalar('Foo: "Bar"') == '"Foo: \\"Bar\\""'


def test_yaml_array_renders_inline():
    assert mf.yaml_array(["a", "b"]) == "[a, b]"
    assert mf.yaml_array([]) == "[]"


def test_yaml_array_quotes_special_chars():
    assert '"a:b"' in mf.yaml_array(["a:b", "plain"])


def test_yaml_array_escapes_internal_quotes():
    """Regression: title legacy 'Foo: \"Bar\"' derivando a aliases producía
    YAML inválido porque yaml_array no escapaba comillas internas."""
    out = mf.yaml_array(['Foo: "Bar"'])
    assert out == '["Foo: \\"Bar\\""]'
    # Y el output debe ser parseable por PyYAML
    import yaml as _yaml
    parsed = _yaml.safe_load(f"x: {out}")
    assert parsed == {"x": ['Foo: "Bar"']}


def test_yaml_array_with_aliases_derived_from_titled_quote():
    """Caso end-to-end: title con `:` y `\"` en build_frontmatter."""
    parsed_classification = {
        "fase": ["Reconocimiento"],
        "plataforma": "Web",
        "dificultad": "Avanzada",
        "mitre": ["T1190"],
    }
    fm = mf.build_frontmatter('Foo: "Bar"', "test", parsed_classification)
    # Parseable por PyYAML
    import yaml as _yaml
    parsed = _yaml.safe_load(fm.split("---\n")[1])
    assert parsed["title"] == 'Foo: "Bar"'
    assert parsed["aliases"] == ['Foo: "Bar"']


# ---------- yaml_scalar: reserved scalars (Finding ronda 4) ----------


# Listas de scalars que PyYAML safe_load REALMENTE resuelve a no-string.
# Verificadas empíricamente con yaml.safe_load(v). YAML 1.1 spec.
_RESOLVES_TO_BOOL = ["No", "no", "NO", "Yes", "yes", "YES",
                      "true", "True", "TRUE", "false", "False", "FALSE",
                      "on", "On", "ON", "off", "Off", "OFF"]
_RESOLVES_TO_NULL = ["null", "Null", "NULL", "~"]
_RESOLVES_TO_NUMBER = ["123", "0", "-7", "+5",
                        "1.5", ".5", "1.0e+10", "1.0e-5",
                        "0xFF", "0xff", "0b101", "0123"]  # YAML 1.1 octal sin 0o
# Finding ronda 5: timestamps y special floats (PyYAML los resuelve).
_RESOLVES_TO_DATE = ["2024-01-01", "1999-12-31"]
_RESOLVES_TO_DATETIME = ["2024-01-01T12:00:00Z", "2024-01-01t12:00:00",
                          "2024-01-01 12:00:00"]
_RESOLVES_TO_SPECIAL_FLOAT = [".nan", ".NaN", ".NAN",
                                ".inf", ".Inf", ".INF",
                                "+.inf", "-.inf"]


@pytest.mark.parametrize(
    "value",
    _RESOLVES_TO_BOOL + _RESOLVES_TO_NULL + _RESOLVES_TO_NUMBER
    + _RESOLVES_TO_DATE + _RESOLVES_TO_DATETIME + _RESOLVES_TO_SPECIAL_FLOAT,
)
def test_yaml_scalar_quotes_pyyaml_implicit_types(value):
    """yaml_scalar debe quotar TODO scalar que PyYAML resuelva a no-string.
    Cubre Findings ronda 4 (bool/null/numbers) y ronda 5 (timestamps,
    special floats). La aproximación robusta es delegar la decisión a
    PyYAML mismo via round-trip (ver _needs_quoting).
    """
    out = mf.yaml_scalar(value)
    assert out.startswith('"') and out.endswith('"'), (
        f"yaml_scalar({value!r}) = {out!r}, debería estar quoted"
    )


@pytest.mark.parametrize(
    "value",
    [
        "Y",  # YAML 1.1 NO resuelve single-char Y/n a bool (sólo yes/no/etc.)
        "n",
        "None",  # YAML usa null/~, no None (Python convention)
        "1e10",  # No matchea float regex (necesita `.`)
        "0o777",  # YAML 1.1 no reconoce prefijo 0o
        "plain",
        "Hello World",
        "Foo (Bar)",
        "Análisis de Vulnerabilidades",
    ],
)
def test_yaml_scalar_does_not_quote_safe_strings(value):
    """Documentar qué strings no requieren quoting porque PyYAML los lee como
    string tal cual. Útil para evitar over-quoting innecesario."""
    out = mf.yaml_scalar(value)
    assert not out.startswith('"'), (
        f"yaml_scalar({value!r}) = {out!r}, no debería estar quoted"
    )


def test_yaml_scalar_empty_string_is_quoted():
    """String vacío debe quotarse para no producir scalar implícito null."""
    assert mf.yaml_scalar("") == '""'


def test_yaml_scalar_rejects_non_string():
    with pytest.raises(TypeError):
        mf.yaml_scalar(123)


# ---------- end-to-end: round-trip via PyYAML ----------


@pytest.mark.parametrize(
    "title",
    [
        "No",  # legacy `# No` debería migrar y round-trip a string "No"
        "Yes",
        "True",
        "null",
        "123",
        "1.5",
        "2024-01-01",  # timestamp
        ".nan",  # special float
        "+.inf",
        'Foo: "Bar"',
        "Plain Title",
        "Análisis de Vulnerabilidades: SQL Injection (SQLi)",
    ],
)
def test_build_frontmatter_round_trip(title):
    """El frontmatter generado debe parsearse de vuelta al string original
    (no a bool/null/int/date/special-float). Cubre Findings rondas 4 y 5."""
    parsed_classification = {
        "fase": ["Reconocimiento"],
        "plataforma": "Web",
        "dificultad": "Avanzada",
        "mitre": ["T1190"],
    }
    fm_block = mf.build_frontmatter(title, "test", parsed_classification)

    import yaml as _yaml
    inner = fm_block.split("---\n", 2)[1]
    parsed = _yaml.safe_load(inner)
    assert parsed["title"] == title, (
        f"round-trip falló: title={title!r} -> emitted -> safe_load -> {parsed['title']!r}"
    )
    assert parsed["aliases"] == [title]
    # Sanity: tipos correctos
    assert isinstance(parsed["title"], str)
    assert isinstance(parsed["slug"], str)
    assert all(isinstance(a, str) for a in parsed["aliases"])


@pytest.mark.parametrize(
    "slug",
    [
        "no",  # Finding ronda 5: legacy `no.md` produciría slug: no -> False
        "yes",
        "true",
        "null",
        "123",  # también pasa kebab-case ^[a-z0-9]+(-[a-z0-9]+)*$
        "0xff",  # idem
    ],
)
def test_build_frontmatter_slug_round_trip(slug):
    """Regression ronda 5: build_frontmatter no pasaba slug por yaml_scalar.
    Un legacy `no.md` migraba a `slug: no` que PyYAML resuelve a False,
    rompiendo después la convención `slug == path.stem`.
    """
    parsed_classification = {
        "fase": ["Reconocimiento"],
        "plataforma": "Web",
        "dificultad": "Avanzada",
        "mitre": ["T1190"],
    }
    fm_block = mf.build_frontmatter("Title", slug, parsed_classification)

    import yaml as _yaml
    inner = fm_block.split("---\n", 2)[1]
    parsed = _yaml.safe_load(inner)
    assert parsed["slug"] == slug
    assert isinstance(parsed["slug"], str)


def test_build_frontmatter_plataforma_dificultad_through_yaml_scalar():
    """Defensivo: aunque los enums actuales (Web/Linux/Avanzada/etc.) no
    colisionan con scalars reservados, la emisión los pasa por yaml_scalar
    para resistir cambios futuros del schema."""
    # Escenario hipotético: si algún día se añade un enum "On" o "1.0", el
    # emisor sigue produciendo YAML válido sin que tenga que reescribirse.
    parsed_classification = {
        "fase": ["Reconocimiento"],
        "plataforma": "On",  # hipotético enum problemático
        "dificultad": "1.0",
        "mitre": ["T1190"],
    }
    fm_block = mf.build_frontmatter("Title", "slug", parsed_classification)
    import yaml as _yaml
    inner = fm_block.split("---\n", 2)[1]
    parsed = _yaml.safe_load(inner)
    assert parsed["plataforma"] == "On"
    assert isinstance(parsed["plataforma"], str)
    assert parsed["dificultad"] == "1.0"
    assert isinstance(parsed["dificultad"], str)


# ---------- extract_h1 / extract_clasificacion_block ----------


def test_extract_h1():
    text = "# Título Real\n\n## Descripción\n"
    assert mf.extract_h1(text) == "Título Real"


def test_extract_h1_returns_none_if_missing():
    assert mf.extract_h1("No H1 here\n") is None


def test_extract_clasificacion_block_simple():
    text = """# T

## Descripción
foo

## Clasificación
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: T1190 (Foo)
- **Plataforma**: Web
- **Dificultad**: Avanzada

## Herramientas
"""
    block, parsed = mf.extract_clasificacion_block(text)
    assert parsed["fase"] == ["Reconocimiento"]
    assert parsed["mitre"] == ["T1190"]
    assert parsed["plataforma"] == "Web"
    assert parsed["dificultad"] == "Avanzada"


def test_extract_clasificacion_compound_fase():
    text = """## Clasificación
- **Fase**: Enumeración, Post-Explotación
- **MITRE ATT&CK**: T1558
- **Plataforma**: Windows
- **Dificultad**: Intermedia

## Herramientas
"""
    _, parsed = mf.extract_clasificacion_block(text)
    assert parsed["fase"] == ["Enumeración", "Post-Explotación"]


def test_extract_clasificacion_multiline_mitre():
    """Bloque MITRE multi-línea con bullets indentados (caso kerberos/docker)."""
    text = """## Clasificación
- **Fase**: Enumeración
- **MITRE ATT&CK**:
    - T1558 (Steal or Forge Kerberos Tickets)
    - T1558.003 (Kerberoasting)
    - T1558.004 (AS-REP Roasting)
- **Plataforma**: Windows
- **Dificultad**: Intermedia

## Herramientas
"""
    _, parsed = mf.extract_clasificacion_block(text)
    assert parsed["mitre"] == ["T1558", "T1558.003", "T1558.004"]


def test_extract_clasificacion_linked_mitre():
    """Caso fingerprinting-tecnologias-web: [T1592.002](url)."""
    text = """## Clasificación
- **Fase**: Reconocimiento
- **MITRE ATT&CK**: [T1592.002](https://attack.mitre.org/techniques/T1592/002/) (Software)
- **Plataforma**: Web
- **Dificultad**: Básica

## Herramientas
"""
    _, parsed = mf.extract_clasificacion_block(text)
    assert parsed["mitre"] == ["T1592.002"]


# ---------- migrate_file end-to-end ----------


def test_migrate_happy_path(tmp_path):
    p = make_legacy_md(
        tmp_path / "test.md",
        title="Mi Técnica",
        fase="Reconocimiento",
        mitre_block="T1190 (Exploit Public-Facing Application)",
        plat="Web",
        dif="Avanzada",
    )
    changed, msg = mf.migrate_file(p, dry_run=False)
    assert changed
    text = p.read_text(encoding="utf-8")
    assert text.startswith("---\n")
    assert "title: Mi Técnica" in text
    assert "slug: test" in text
    assert "## Clasificación" not in text
    assert "## Herramientas" in text  # body intact


def test_migrate_skips_existing_frontmatter(tmp_path):
    p = tmp_path / "test.md"
    p.write_text("---\ntitle: x\n---\n\n# x\n", encoding="utf-8")
    changed, msg = mf.migrate_file(p, dry_run=False)
    assert not changed
    assert "already has frontmatter" in msg


def test_migrate_skips_no_clasificacion(tmp_path):
    p = tmp_path / "test.md"
    p.write_text("# Title\n\n## Descripción\nFoo\n", encoding="utf-8")
    changed, msg = mf.migrate_file(p, dry_run=False)
    assert not changed
    assert "no Clasificación" in msg


def test_migrate_quotes_title_with_colon(tmp_path):
    p = make_legacy_md(
        tmp_path / "test.md",
        title="Análisis: SQLi",
        fase="Análisis de Vulnerabilidades",
        mitre_block="T1190",
        plat="Web",
        dif="Avanzada",
    )
    mf.migrate_file(p, dry_run=False)
    text = p.read_text(encoding="utf-8")
    assert 'title: "Análisis: SQLi"' in text


def test_migrate_dry_run_does_not_write(tmp_path):
    p = make_legacy_md(
        tmp_path / "test.md",
        title="X",
        fase="Reconocimiento",
        mitre_block="T1190",
        plat="Web",
        dif="Básica",
    )
    original = p.read_text(encoding="utf-8")
    mf.migrate_file(p, dry_run=True)
    assert p.read_text(encoding="utf-8") == original


def test_migrate_empty_mitre_allowed_for_fundamentos(tmp_path):
    """Conceptual content puede tener MITRE vacío."""
    p = tmp_path / "test.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    content = """# Modelo OSI

## Descripción
Foo.

## Clasificación
- **Fase**: Fundamentos
- **MITRE ATT&CK**:
- **Plataforma**: Red
- **Dificultad**: Básica

## Referencias
- Foo
"""
    p.write_text(content, encoding="utf-8")
    changed, msg = mf.migrate_file(p, dry_run=False)
    assert changed, msg


def test_migrate_empty_mitre_rejected_for_non_conceptual(tmp_path):
    p = tmp_path / "test.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    content = """# X

## Descripción
Foo.

## Clasificación
- **Fase**: Reconocimiento
- **MITRE ATT&CK**:
- **Plataforma**: Web
- **Dificultad**: Básica

## Referencias
"""
    p.write_text(content, encoding="utf-8")
    changed, msg = mf.migrate_file(p, dry_run=False)
    assert not changed
    assert "missing mitre" in msg


def test_migrate_validates_enum_plataforma(tmp_path):
    p = make_legacy_md(
        tmp_path / "test.md",
        title="X",
        fase="Reconocimiento",
        mitre_block="T1190",
        plat="Mainframe",  # inválido
        dif="Básica",
    )
    changed, msg = mf.migrate_file(p, dry_run=False)
    assert not changed
    assert "invalid plataforma" in msg
