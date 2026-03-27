"""
conftest.py — Configurazione globale di pytest per SE-OFFLINE-PAYMENTS

Registra i marker personalizzati usati nei test, evitando avvisi
di "unknown mark" durante l'esecuzione della suite.
"""

import pytest


def pytest_configure(config):
    """Registra i marker personalizzati."""
    config.addinivalue_line(
        "markers",
        "hardware: test che richiedono hardware reale (lettore ACR122U + smart card)"
    )
