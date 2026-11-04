#!/usr/bin/env sh
# Avvia la demo dei pagamenti offline su Linux / macOS:  sh avvia_demo.sh
cd "$(dirname "$0")" || exit 1
python3 -m pip install --quiet "cryptography>=41.0.0"
python3 demo.py --passo
