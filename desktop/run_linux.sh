#!/usr/bin/env bash
cd "$(dirname "$0")"
if ! command -v python3 >/dev/null 2>&1; then
  echo "Python 3 nao encontrado."; exit 1
fi
python3 aegis_app.py
