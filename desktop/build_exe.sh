#!/usr/bin/env bash
cd "$(dirname "$0")"
python3 -m pip install --upgrade pyinstaller
python3 -m PyInstaller --noconfirm --onefile --windowed --name AEGIS --add-data "assets:assets" --add-data "config.json:." aegis_app.py
echo "Pronto: dist/AEGIS"
