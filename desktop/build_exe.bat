@echo off
cd /d "%~dp0"
echo Instalando o PyInstaller...
python -m pip install --upgrade pyinstaller
echo Gerando o executavel...
python -m PyInstaller --noconfirm --onefile --windowed --name AEGIS --icon assets\aegis.ico --add-data "assets;assets" --add-data "config.json;." aegis_app.py
echo.
echo Pronto: dist\AEGIS.exe
pause
