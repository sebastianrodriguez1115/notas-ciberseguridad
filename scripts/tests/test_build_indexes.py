"""Tests para scripts/build_indexes.py."""
from __future__ import annotations

import sys
from pathlib import Path

import build_indexes as bi


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
    monkeypatch.setattr(bi, "REPO_ROOT", sandbox)
    monkeypatch.setattr(bi, "INVENTORY", sandbox / "inventario")
    monkeypatch.setattr(bi, "META_DIR", sandbox / "inventario" / "meta")


# ---------- short_title ----------


def test_short_title_strips_prefix():
    assert bi.short_title("Análisis de Vulnerabilidades: SQLi") == "SQLi"


def test_short_title_no_colon_unchanged():
    assert bi.short_title("Banner Grabbing HTTP") == "Banner Grabbing HTTP"


def test_short_title_only_first_colon():
    """Si el title tiene varios `:`, sólo split por el primero."""
    assert bi.short_title("Foo: Bar: Baz") == "Bar: Baz"


# ---------- render_table ----------


def test_render_table_format():
    rows = [
        ("SQLi", "./analisis-sqli.md", "T1190", "Avanzada", "Web"),
        ("XSS", "./analisis-xss.md", "T1190", "Intermedia", "Web"),
    ]
    table = bi.render_table(rows)
    assert table.startswith("| Técnica | MITRE | Dificultad | Plataforma |\n| :---")
    assert "[SQLi](./analisis-sqli.md)" in table
    assert "T1190 | Avanzada | Web" in table


# ---------- collect_files ----------


def test_collect_files_excludes_index_template_meta(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    inv = sandbox / "inventario"
    write_md(inv / "real.md", VALID_FM)
    (inv / "INDEX.md").write_text("# index", encoding="utf-8")
    (inv / "TEMPLATE.md").write_text("# template", encoding="utf-8")
    (inv / "meta").mkdir()
    (inv / "meta" / "by-mitre.md").write_text("# meta", encoding="utf-8")
    files = bi.collect_files()
    assert len(files) == 1
    assert files[0][0].name == "real.md"


# ---------- regen_leaf_index ----------


def test_regen_leaf_index_basic(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    leaf = sandbox / "inventario" / "01-reconocimiento" / "pasivo"
    write_md(leaf / "tech-a.md", dict(VALID_FM, slug="tech-a", title="Técnica A"))
    write_md(leaf / "tech-b.md", dict(VALID_FM, slug="tech-b", title="Técnica B"))
    (leaf / "INDEX.md").write_text(
        "# Reconocimiento Pasivo\n\nDescripción narrativa.\n\n",
        encoding="utf-8",
    )
    files = bi.collect_files()
    new = bi.regen_leaf_index(leaf, files)
    assert "# Reconocimiento Pasivo" in new
    assert "Descripción narrativa." in new
    assert bi.AUTOGEN_NOTICE in new
    assert "[Técnica A](./tech-a.md)" in new
    assert "[Técnica B](./tech-b.md)" in new


def test_regen_leaf_index_idempotent(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    leaf = sandbox / "inventario" / "01-reconocimiento" / "pasivo"
    write_md(leaf / "x.md", dict(VALID_FM, slug="x", title="X"))
    (leaf / "INDEX.md").write_text("# Pasivo\n\nNarrativa.\n", encoding="utf-8")
    files = bi.collect_files()
    first = bi.regen_leaf_index(leaf, files)
    (leaf / "INDEX.md").write_text(first, encoding="utf-8")
    files = bi.collect_files()
    second = bi.regen_leaf_index(leaf, files)
    assert first == second


def test_regen_leaf_index_preserves_narrative(monkeypatch, sandbox, write_md):
    """Si re-ejecutamos, la narrativa antes del marcador AUTOGEN se mantiene."""
    patch_paths(monkeypatch, sandbox)
    leaf = sandbox / "inventario" / "02-enumeracion" / "web"
    write_md(leaf / "x.md", dict(VALID_FM, slug="x", title="X", fase=["Enumeración"]))
    (leaf / "INDEX.md").write_text(
        "# Enumeración: Web\n\nNarrativa única.\n\n",
        encoding="utf-8",
    )
    files = bi.collect_files()
    first = bi.regen_leaf_index(leaf, files)
    (leaf / "INDEX.md").write_text(first, encoding="utf-8")
    files = bi.collect_files()
    second = bi.regen_leaf_index(leaf, files)
    assert "Narrativa única." in second
    # No duplicación del marcador AUTOGEN
    assert second.count(bi.AUTOGEN_NOTICE) == 1


def test_regen_leaf_index_backlink_one_level(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    leaf = sandbox / "inventario" / "01-reconocimiento" / "pasivo"
    write_md(leaf / "x.md", dict(VALID_FM, slug="x", title="X"))
    (leaf / "INDEX.md").write_text("# Pasivo\n\n", encoding="utf-8")
    files = bi.collect_files()
    new = bi.regen_leaf_index(leaf, files)
    assert "[Volver a Reconocimiento](../INDEX.md)" in new


def test_regen_leaf_index_backlink_two_levels(monkeypatch, sandbox, write_md):
    """privilege-escalation/linux/ tiene fase 2 niveles arriba."""
    patch_paths(monkeypatch, sandbox)
    leaf = sandbox / "inventario" / "05-post-explotacion" / "privilege-escalation" / "linux"
    write_md(
        leaf / "x.md",
        dict(VALID_FM, slug="x", title="X", fase=["Post-Explotación"]),
    )
    (leaf / "INDEX.md").write_text("# Linux Privesc\n\n", encoding="utf-8")
    files = bi.collect_files()
    new = bi.regen_leaf_index(leaf, files)
    assert "[Volver a Post-Explotación](../../INDEX.md)" in new


def test_regen_leaf_index_sorted_by_display_title(monkeypatch, sandbox, write_md):
    """El sort key es el display title (post short_title), no el title completo."""
    patch_paths(monkeypatch, sandbox)
    leaf = sandbox / "inventario" / "03-analisis-vulnerabilidades" / "web"
    write_md(
        leaf / "a.md",
        dict(
            VALID_FM,
            slug="a",
            title="Análisis de Vulnerabilidades: Z Topic",  # display=Z Topic
            fase=["Análisis de Vulnerabilidades"],
        ),
    )
    write_md(
        leaf / "b.md",
        dict(
            VALID_FM,
            slug="b",
            title="A Topic",  # display=A Topic
            fase=["Análisis de Vulnerabilidades"],
        ),
    )
    (leaf / "INDEX.md").write_text("# Web\n\n", encoding="utf-8")
    files = bi.collect_files()
    new = bi.regen_leaf_index(leaf, files)
    a_pos = new.find("A Topic")
    z_pos = new.find("Z Topic")
    assert 0 < a_pos < z_pos, "rows debe ordenarse por display title"


# ---------- TOPICS / facets ----------


def test_build_topics_includes_all_slugs(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    inv = sandbox / "inventario"
    write_md(inv / "fase01" / "a.md", dict(VALID_FM, slug="a", title="A"))
    write_md(inv / "fase02" / "b.md", dict(VALID_FM, slug="b", title="B"))
    files = bi.collect_files()
    topics = bi.build_topics(files)
    assert "## `a`" in topics
    assert "## `b`" in topics


def test_build_facet_groups_correctly(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    inv = sandbox / "inventario"
    write_md(inv / "fase01" / "a.md", dict(VALID_FM, slug="a", dificultad="Avanzada"))
    write_md(inv / "fase01" / "b.md", dict(VALID_FM, slug="b", dificultad="Básica"))
    files = bi.collect_files()
    out = bi.build_facet_index(
        files, "by-difficulty", "Inventario por Dificultad", lambda fm: [fm.get("dificultad", "—")]
    )
    assert "## Avanzada (1)" in out
    assert "## Básica (1)" in out


# ---------- main with --check ----------


def test_check_mode_does_not_create_meta_dir(monkeypatch, sandbox, write_md, capsys):
    """Finding 4 del review: --check no debe crear inventario/meta/."""
    patch_paths(monkeypatch, sandbox)
    inv = sandbox / "inventario"
    write_md(inv / "fase01" / "a.md", dict(VALID_FM, slug="a"))

    # Ejecutar build_indexes en modo --check
    monkeypatch.setattr(sys, "argv", ["build_indexes.py", "--check"])
    try:
        bi.main()
    except SystemExit:
        pass

    # meta/ NO debe haberse creado
    assert not (inv / "meta").exists(), "--check no debe crear inventario/meta/"


def test_check_mode_does_not_modify_files(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    inv = sandbox / "inventario"
    leaf = inv / "fase01"
    write_md(leaf / "a.md", dict(VALID_FM, slug="a"))
    (leaf / "INDEX.md").write_text("# Original\n\n", encoding="utf-8")

    original = (leaf / "INDEX.md").read_text(encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["build_indexes.py", "--check"])
    try:
        bi.main()
    except SystemExit:
        pass
    # INDEX.md no debe haber cambiado
    assert (leaf / "INDEX.md").read_text(encoding="utf-8") == original


def test_full_run_writes_files(monkeypatch, sandbox, write_md):
    patch_paths(monkeypatch, sandbox)
    inv = sandbox / "inventario"
    leaf = inv / "01-reconocimiento" / "pasivo"
    write_md(leaf / "a.md", dict(VALID_FM, slug="a"))
    (leaf / "INDEX.md").write_text("# Pasivo\n\n", encoding="utf-8")

    monkeypatch.setattr(sys, "argv", ["build_indexes.py"])
    try:
        bi.main()
    except SystemExit:
        pass

    assert (inv / "TOPICS.md").exists()
    assert (inv / "meta" / "by-mitre.md").exists()
    assert bi.AUTOGEN_NOTICE in (leaf / "INDEX.md").read_text(encoding="utf-8")
