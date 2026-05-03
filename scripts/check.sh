#!/usr/bin/env bash
# Ritual de verificación pre-commit. Falla en cuanto un step falla.
# Cubre: tests unitarios + validación de frontmatter + idempotencia de índices.
#
# Uso:
#     bash scripts/check.sh
#
# Por qué existe: la sesión 19g del CHANGELOG documenta el caso donde se
# arregló data en un .md sin re-correr build_indexes, dejando los índices
# stale aunque validate pasara. Este script garantiza que las tres puertas
# se crucen en orden.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> 1/3 pytest"
python3 -m pytest scripts/tests/ -q

echo
echo "==> 2/3 validate frontmatter"
python3 scripts/validate.py --quiet

echo
echo "==> 3/3 build_indexes --check (idempotencia)"
python3 scripts/build_indexes.py --check

echo
echo "all green"
