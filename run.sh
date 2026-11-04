#!/usr/bin/env bash
# Démarre VulnLens sur http://localhost:8000
set -euo pipefail
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "→ Création de l'environnement virtuel…"
  python3 -m venv .venv
fi

echo "→ Installation des dépendances…"
.venv/bin/pip install --quiet --upgrade pip
.venv/bin/pip install --quiet -r requirements.txt

echo "→ Lancement sur http://localhost:8000"
exec .venv/bin/python -m uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8000}" "$@"
