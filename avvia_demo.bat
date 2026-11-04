@echo off
REM Avvia la demo dei pagamenti offline su Windows (doppio clic su questo file)
cd /d "%~dp0"
python -m pip install --quiet "cryptography>=41.0.0"
python demo.py --passo
echo.
echo Ora la modalita' privacy (monete con firma cieca)
python demo_privacy.py --passo
pause
