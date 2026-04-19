#!/usr/bin/env bash
# Patch-Learner dashboard launcher (WSL / Git Bash friendly)
set -e
cd "$(dirname "$0")"

if [ ! -d .venv ]; then
  echo "[run] creating venv..."
  python -m venv .venv
fi

echo "[run] activating venv..."
# shellcheck source=/dev/null
source .venv/Scripts/activate 2>/dev/null || source .venv/bin/activate

echo "[run] installing requirements..."
python -m pip install --quiet --upgrade pip
python -m pip install --quiet -r requirements.txt

echo "[run] launching http://127.0.0.1:8787 ..."
python app.py
