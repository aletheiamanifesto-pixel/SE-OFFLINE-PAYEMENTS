@echo off
REM Avvia la demo dei pagamenti offline su Windows (doppio clic su questo file)
cd /d "%~dp0"
python -m pip install --quiet "cryptography>=41.0.0"
python demo.py --passo
pause
