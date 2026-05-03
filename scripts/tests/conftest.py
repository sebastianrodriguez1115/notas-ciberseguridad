"""
Fixtures compartidas entre tests de scripts/.

Estrategia: cada test que necesite filesystem trabaja en un tmp_path
de pytest y monkeypatchea las constantes globales del módulo bajo test
(REPO_ROOT, INVENTORY, LEARNING) para apuntar al sandbox.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Permitir importar `validate`, `build_indexes`, `migrate_frontmatter` desde scripts/
SCRIPTS_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SCRIPTS_DIR))


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    """Estructura de repo de prueba con inventario/ y learning/ vacíos."""
    inventory = tmp_path / "inventario"
    learning = tmp_path / "learning"
    inventory.mkdir()
    learning.mkdir()
    return tmp_path


def _write_md(path: Path, frontmatter: dict | None, body: str = "# Test\n\nDescripción.\n") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    if frontmatter is None:
        path.write_text(body, encoding="utf-8")
        return path

    lines = ["---"]
    for k, v in frontmatter.items():
        if isinstance(v, list):
            inner = ", ".join(f'"{x}"' if isinstance(x, str) and ":" in x else str(x) for x in v)
            lines.append(f"{k}: [{inner}]")
        elif isinstance(v, str) and ":" in v:
            lines.append(f'{k}: "{v}"')
        else:
            lines.append(f"{k}: {v}")
    lines.append("---")
    lines.append("")
    lines.append(body)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


@pytest.fixture
def write_md():
    """Helper: crea un .md con frontmatter dado. Uso: write_md(path, fm, body)."""
    return _write_md
