"""Tests para scripts/validate.py."""
from __future__ import annotations

from pathlib import Path

import pytest

import validate
VALID_FM = {
    "title": "Test",
    "slug": "test",
    "aliases": ["Test"],
    "fase": ["Reconocimiento"],
    "plataforma": "Web",
    "dificultad": "Avanzada",
    "mitre": ["T1190"],
}


def patch_paths(monkeypatch, sandbox: Path):
    monkeypatch.setattr(validate, "REPO_ROOT", sandbox)
    monkeypatch.setattr(validate, "INVENTORY", sandbox / "inventario")
    monkeypatch.setattr(validate, "LEARNING", sandbox / "learning")


# ---------- happy path ----------


def test_valid_frontmatter_passes(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    p = write_md(sandbox / "inventario" / "test.md", VALID_FM)
    errors = validate.validate_file(p, {})
    assert errors == []


def test_collect_files_excludes_index_template_meta_topics(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    inv = sandbox / "inventario"
    write_md(inv / "real.md", VALID_FM)
    write_md(inv / "INDEX.md", None, "# index")
    write_md(inv / "TEMPLATE.md", None, "# template")
    write_md(inv / "TOPICS.md", None, "# topics")
    write_md(inv / "meta" / "by-mitre.md", None, "# by mitre")
    files = validate.collect_files()
    assert {f.name for f in files} == {"real.md"}


# ---------- required fields ----------


def test_missing_required_field_reports_error(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    fm = dict(VALID_FM)
    del fm["mitre"]
    p = write_md(sandbox / "inventario" / "test.md", fm)
    errors = validate.validate_file(p, {})
    assert any("missing required field: mitre" in e for e in errors)


def test_no_frontmatter_reported(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    p = write_md(sandbox / "inventario" / "test.md", None, body="# Just H1\n")
    errors = validate.validate_file(p, {})
    assert any("no frontmatter" in e for e in errors)


# ---------- enum validation ----------


def test_invalid_plataforma(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    fm = dict(VALID_FM, plataforma="Mainframe")
    p = write_md(sandbox / "inventario" / "test.md", fm)
    errors = validate.validate_file(p, {})
    assert any("invalid plataforma" in e for e in errors)


def test_invalid_dificultad(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    fm = dict(VALID_FM, dificultad="Media")
    p = write_md(sandbox / "inventario" / "test.md", fm)
    errors = validate.validate_file(p, {})
    assert any("invalid dificultad" in e for e in errors)


def test_invalid_fase_value(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    fm = dict(VALID_FM, fase=["Recon"])  # incorrect — debería ser "Reconocimiento"
    p = write_md(sandbox / "inventario" / "test.md", fm)
    errors = validate.validate_file(p, {})
    assert any("invalid fase value" in e for e in errors)


# ---------- defensive type checks (Finding 2 del review) ----------


def test_plataforma_as_list_no_crash(monkeypatch, sandbox):
    """Regression: plataforma: [Web] solía crashear con TypeError."""
    patch_paths(monkeypatch, sandbox)
    raw = """---
title: Test
slug: test
aliases: []
fase: [Reconocimiento]
plataforma: [Web]
dificultad: Avanzada
mitre: [T1190]
---
# Test
"""
    p = sandbox / "inventario" / "test.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(raw, encoding="utf-8")
    errors = validate.validate_file(p, {})
    assert any("plataforma must be string" in e for e in errors)


def test_title_as_int_no_crash(monkeypatch, sandbox):
    patch_paths(monkeypatch, sandbox)
    raw = """---
title: 42
slug: test
aliases: []
fase: [Reconocimiento]
plataforma: Web
dificultad: Avanzada
mitre: [T1190]
---
# Test
"""
    p = sandbox / "inventario" / "test.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(raw, encoding="utf-8")
    errors = validate.validate_file(p, {})
    assert any("title must be string" in e for e in errors)


def test_fase_as_string_not_array(monkeypatch, sandbox):
    patch_paths(monkeypatch, sandbox)
    raw = """---
title: Test
slug: test
aliases: []
fase: Reconocimiento
plataforma: Web
dificultad: Avanzada
mitre: [T1190]
---
# Test
"""
    p = sandbox / "inventario" / "test.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(raw, encoding="utf-8")
    errors = validate.validate_file(p, {})
    assert any("fase must be array" in e for e in errors)


def test_related_with_non_string_item(monkeypatch, sandbox):
    """Regression: related: [123, 'foo'] no debe crashear."""
    patch_paths(monkeypatch, sandbox)
    raw = """---
title: Test
slug: test
aliases: []
fase: [Reconocimiento]
plataforma: Web
dificultad: Avanzada
mitre: [T1190]
related: [123, "valid"]
learning_refs: []
---
# Test
"""
    p = sandbox / "inventario" / "test.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(raw, encoding="utf-8")
    errors = validate.validate_file(p, {})
    assert any("related item must be string" in e for e in errors)


# ---------- title vs H1 ----------


def test_title_h1_match_passes(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    p = write_md(sandbox / "inventario" / "test.md", VALID_FM, body="# Test\n\nfoo\n")
    errors = validate.validate_file(p, {})
    assert errors == []


def test_title_h1_mismatch_reported(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    p = write_md(sandbox / "inventario" / "test.md", VALID_FM, body="# Different H1\n\nfoo\n")
    errors = validate.validate_file(p, {})
    assert any("title mismatch" in e for e in errors)


def test_no_h1_reported(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    p = write_md(sandbox / "inventario" / "test.md", VALID_FM, body="No H1 here\n")
    errors = validate.validate_file(p, {})
    assert any("body has no H1" in e for e in errors)


# ---------- MITRE ----------


def test_invalid_mitre_format(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    fm = dict(VALID_FM, mitre=["T119"])  # 3 dígitos en lugar de 4
    p = write_md(sandbox / "inventario" / "test.md", fm)
    errors = validate.validate_file(p, {})
    assert any("invalid mitre ID" in e for e in errors)


def test_empty_mitre_allowed_for_fundamentos(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    fm = dict(VALID_FM, fase=["Fundamentos"], mitre=[])
    p = write_md(sandbox / "inventario" / "test.md", fm)
    errors = validate.validate_file(p, {})
    assert all("empty mitre" not in e for e in errors)


def test_empty_mitre_rejected_otherwise(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    fm = dict(VALID_FM, mitre=[])
    p = write_md(sandbox / "inventario" / "test.md", fm)
    errors = validate.validate_file(p, {})
    assert any("empty mitre" in e for e in errors)


# ---------- slug shape (kebab-case + igual a filename) ----------


def test_slug_must_equal_filename(monkeypatch, sandbox, write_md):
    """Finding 2 ronda 2: slug != filename debe rechazarse."""
    patch_paths(monkeypatch, sandbox)
    fm = dict(VALID_FM, slug="sqli")
    p = write_md(sandbox / "inventario" / "analisis-sqli.md", fm)
    errors = validate.validate_file(p, {})
    assert any("must equal filename" in e for e in errors)


def test_slug_kebab_case_rejected_uppercase(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    fm = dict(VALID_FM, slug="Test-Slug")
    p = write_md(sandbox / "inventario" / "Test-Slug.md", fm)
    errors = validate.validate_file(p, {})
    assert any("not in kebab-case" in e for e in errors)


def test_slug_kebab_case_rejected_underscore(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    fm = dict(VALID_FM, slug="test_slug")
    p = write_md(sandbox / "inventario" / "test_slug.md", fm)
    errors = validate.validate_file(p, {})
    assert any("not in kebab-case" in e for e in errors)


def test_slug_kebab_case_passes_simple(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    fm = dict(VALID_FM, slug="analisis-sqli")
    p = write_md(sandbox / "inventario" / "analisis-sqli.md", fm)
    errors = validate.validate_file(p, {})
    assert all("kebab-case" not in e and "filename" not in e for e in errors)


# ---------- slug uniqueness ----------


def test_duplicate_slug_reported(monkeypatch, sandbox, write_md):
    """Caso real: mismo nombre de archivo en distintos directorios produce
    slug duplicado. Con slug=filename + slug uniqueness, esto se detecta."""
    patch_paths(monkeypatch, sandbox)
    inv = sandbox / "inventario"
    p1 = write_md(inv / "pasivo" / "shared.md", dict(VALID_FM, slug="shared"))
    p2 = write_md(inv / "activo" / "shared.md", dict(VALID_FM, slug="shared"))
    all_slugs: dict = {}
    validate.validate_file(p1, all_slugs)
    errors = validate.validate_file(p2, all_slugs)
    assert any("duplicate slug" in e for e in errors)


# ---------- body still has Clasificación ----------


def test_body_with_clasificacion_section_rejected(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    body = "# Test\n\n## Clasificación\n- **Fase**: Reconocimiento\n"
    p = write_md(sandbox / "inventario" / "test.md", VALID_FM, body=body)
    errors = validate.validate_file(p, {})
    assert any("Clasificación" in e for e in errors)


# ---------- cross_validate (related + learning_refs) ----------


def test_related_dangling_reported(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    fm = dict(VALID_FM, related=["nonexistent"], learning_refs=[])
    p = write_md(sandbox / "inventario" / "test.md", fm)
    files_data = {p: {"related": ["nonexistent"], "learning_refs": []}}
    cross = validate.cross_validate(files_data, {"test": p})
    assert p in cross
    assert any("does not exist" in e for e in cross[p])


def test_learning_refs_missing_writeup(monkeypatch, sandbox, write_md):
    """Finding 3b: directorio sin writeup.md debe ser rechazado."""
    patch_paths(monkeypatch, sandbox)
    (sandbox / "learning" / "foo").mkdir(parents=True)
    (sandbox / "learning" / "foo" / "notes.md").write_text("notes", encoding="utf-8")
    fm = dict(VALID_FM, related=[], learning_refs=["foo"])
    p = write_md(sandbox / "inventario" / "test.md", fm)
    files_data = {p: {"related": [], "learning_refs": ["foo"]}}
    cross = validate.cross_validate(files_data, {"test": p})
    assert p in cross
    assert any("missing writeup.md" in e for e in cross[p])


def test_learning_refs_with_writeup_passes(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    (sandbox / "learning" / "foo").mkdir(parents=True)
    (sandbox / "learning" / "foo" / "writeup.md").write_text("# writeup", encoding="utf-8")
    fm = dict(VALID_FM, related=[], learning_refs=["foo"])
    p = write_md(sandbox / "inventario" / "test.md", fm)
    files_data = {p: {"related": [], "learning_refs": ["foo"]}}
    cross = validate.cross_validate(files_data, {"test": p})
    assert p not in cross


def test_learning_refs_path_does_not_exist(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    fm = dict(VALID_FM, related=[], learning_refs=["nonexistent-dir"])
    p = write_md(sandbox / "inventario" / "test.md", fm)
    files_data = {p: {"related": [], "learning_refs": ["nonexistent-dir"]}}
    cross = validate.cross_validate(files_data, {"test": p})
    assert p in cross
    assert any("path does not exist" in e for e in cross[p])


# ---------- main: cross_validate failure forces non-zero exit ----------


def test_cross_validate_skips_non_list_related(monkeypatch, sandbox, write_md):
    """Regression: si related no es lista (ej. string), cross_validate no
    debe iterarla carácter por carácter generando errores falsos."""
    patch_paths(monkeypatch, sandbox)
    p = sandbox / "inventario" / "test.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("# x\n", encoding="utf-8")
    files_data = {p: {"related": "foo", "learning_refs": []}}
    cross = validate.cross_validate(files_data, {})
    # No debe haber 3 errores (uno por cada carácter de "foo")
    assert p not in cross or all(
        "'f'" not in e and "'o'" not in e for e in cross.get(p, [])
    )


def test_cross_validate_skips_non_list_learning_refs(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    p = sandbox / "inventario" / "test.md"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("# x\n", encoding="utf-8")
    files_data = {p: {"related": [], "learning_refs": "foo"}}
    cross = validate.cross_validate(files_data, {})
    # No debe iterar la string como path por carácter
    assert p not in cross or all(
        "'f'" not in e and "'o'" not in e for e in cross.get(p, [])
    )


def test_main_exits_nonzero_when_cross_validate_crashes(monkeypatch, sandbox, write_md, capsys):
    """Finding 3 ronda 2: si cross_validate crashea, el comando debe fallar
    aunque no haya errores per-file."""
    patch_paths(monkeypatch, sandbox)
    write_md(sandbox / "inventario" / "test.md", VALID_FM)

    # Forzar crash inyectando un cross_validate roto
    def boom(*a, **kw):
        raise RuntimeError("simulated cross-validate crash")

    monkeypatch.setattr(validate, "cross_validate", boom)
    monkeypatch.setattr("sys.argv", ["validate.py"])

    with pytest.raises(SystemExit) as exc:
        validate.main()
    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "FATAL" in captured.err
    assert "marcando como failure" in captured.out
